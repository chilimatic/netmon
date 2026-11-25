//! Hostnames from DNS answers and TLS SNI.

use super::*;

/// TCP DNS connections remembered as read at most.
const MAX_TCP_DNS: usize = 4096;
/// Blocked addresses at most (HOST_BLOCKS holds 16 384), and per name.
pub(crate) const MAX_BLOCKED: usize = 8192;
const MAX_ADDRS_PER_NAME: usize = 64;

impl<K: Kernel> Monitor<K> {
    /// Reads new DNS answers and ClientHellos and names every flow's
    /// remote end. The TLS server name wins: it is what the client asked
    /// this server for, while one address can serve many DNS names.
    pub(crate) fn refresh_hosts(&mut self, now: Instant) {
        self.poll_names(now);
        self.log_dns();
        // Names of connections that are gone.
        let flows = &self.collector.flows;
        self.sni.retain(|k, _| flows.contains_key(k));
        self.tcp_dns_seen.retain(|k| flows.contains_key(k));
        self.hello_parts.retain(|k, _| flows.contains_key(k));
        for (k, f) in self.collector.flows.iter_mut() {
            // Dual-stack sockets show IPv4 peers as ::ffff:a.b.c.d.
            let ip = procmap::normalize(f.remote).ip();
            (f.host, f.host_source) = match (self.sni.get(k), self.hosts.get(ip, now)) {
                (Some(n), _) => (Some(n.clone()), "tls"),
                (None, Some(n)) => (Some(n.to_string()), "dns"),
                (None, None) => (None, ""),
            };
        }
    }

    /// Reads new DNS answers and ClientHellos. An address of a blocked
    /// hostname goes to the kernel at once. Returns whether it found one.
    ///
    /// Only answers of a trusted resolver (a nameserver of resolv.conf, or
    /// a local stub on loopback) can block addresses: any local program
    /// can ask its own DNS server or send a ClientHello with any name.
    pub(crate) fn poll_names(&mut self, now: Instant) -> bool {
        let mut learned: Vec<(std::net::IpAddr, String)> = Vec::new();
        let resolvers = crate::learn::resolvers(&self.guard.resolv);
        let (hosts, trusted, sni, parts, dns, tcp_seen) = (
            &mut self.hosts,
            &mut self.trusted_hosts,
            &mut self.sni,
            &mut self.hello_parts,
            &mut self.dns_pending,
            &mut self.tcp_dns_seen,
        );
        let unix = rules::unix_now();
        self.probe.drain_names(NAME_BATCH, |ev| {
            let data = &ev.data[..(ev.len as usize).min(ev.data.len())];
            // DNS over TCP: the message follows a 2-byte length, in the
            // first segment of the connection only. A later segment can be
            // the middle of a long answer.
            let (kind, data) = match ev.kind {
                netmon_common::NAME_DNS_TCP if data.len() >= 14 && tcp_seen.len() < MAX_TCP_DNS && tcp_seen.insert(ev.key) => {
                    (netmon_common::NAME_DNS, &data[2..])
                }
                netmon_common::NAME_DNS_TCP => (0, data),
                k => (k, data),
            };
            let server = procmap::normalize(collector::addr(ev.key.family, &ev.key.remote_addr, 0)).ip();
            let from_resolver = server.is_loopback() || resolvers.contains(&server);
            match kind {
                netmon_common::NAME_DNS => {
                    if let Some(a) = names::dns_answer(data)
                        && dns.len() < crate::dnslog::MAX_ENTRIES
                    {
                        dns.push((
                            ev.key,
                            crate::dnslog::DnsEntry {
                                time: unix,
                                program: String::new(),
                                pid: None,
                                server,
                                name: a.name,
                                qtype: names::qtype_text(a.qtype),
                                rcode: names::rcode_text(a.rcode),
                                answers: a.answers,
                                blocked: false,
                            },
                        ));
                    }
                    for (ip, name, _ttl) in names::dns_answers(data) {
                        if from_resolver {
                            learned.push((ip, name.clone()));
                            trusted.insert(ip, name.clone(), now);
                        }
                        hosts.insert(ip, name, now);
                    }
                }
                netmon_common::NAME_TLS => match names::client_hello_sni(data) {
                    // A server name names the flow only: the kernel drops a
                    // ClientHello with a blocked name itself.
                    Some(name) => {
                        sni.insert(ev.key, name);
                    }
                    None if names::record_continues(data) => {
                        if parts.len() >= MAX_HELLO_PARTS {
                            parts.clear();
                        }
                        parts.insert(ev.key, data.to_vec());
                    }
                    None => {}
                },
                netmon_common::NAME_TLS_CONT => {
                    if let Some(mut hello) = parts.remove(&ev.key) {
                        hello.extend_from_slice(data);
                        if let Some(name) = names::client_hello_sni(&hello) {
                            sni.insert(ev.key, name);
                        }
                    }
                }
                _ => {}
            }
        });
        let mut found = false;
        for (ip, name) in learned {
            if self.rules.host_pattern_blocked(&name) {
                let ip = procmap::normalize(std::net::SocketAddr::new(ip, 0)).ip();
                found |= self.block_address(ip, name, now);
            }
        }
        if found {
            let _ = self.sync_host_blocks(now);
        }
        found
    }

    /// Moves the answers read since the last tick into the DNS log, with
    /// the program that owns the asking socket. The owners are resolved at
    /// this point of the tick.
    pub(crate) fn log_dns(&mut self) {
        for (k, mut e) in std::mem::take(&mut self.dns_pending) {
            if let Some(f) = self.collector.flows.get(&k) {
                e.program = crate::usage::program(f);
                e.pid = f.owner.as_ref().map(|o| o.pid);
            } else {
                e.program = crate::usage::UNKNOWN.into();
            }
            e.blocked = self.rules.host_blocked(&e.name);
            if self.dns_log.len() >= crate::dnslog::MAX_ENTRIES {
                self.dns_log.pop_front();
            }
            self.dns_log.push_back(e.clone());
            if self.new_dns.len() < crate::dnslog::MAX_ENTRIES {
                self.new_dns.push(e);
            }
        }
    }

    /// Adds an address of a blocked name. At most MAX_ADDRS_PER_NAME per
    /// name; when MAX_BLOCKED is reached, the oldest address goes.
    /// Returns whether the address is new.
    pub(crate) fn block_address(&mut self, ip: std::net::IpAddr, name: String, now: Instant) -> bool {
        if let Some(e) = self.blocked.get_mut(&ip) {
            *e = (name, now);
            return false;
        }
        if self.blocked.values().filter(|(n, _)| *n == name).count() >= MAX_ADDRS_PER_NAME {
            return false;
        }
        if self.blocked.len() >= MAX_BLOCKED
            && let Some(old) = self.blocked.iter().min_by_key(|(_, (_, seen))| *seen).map(|(ip, _)| *ip)
        {
            self.blocked.remove(&old);
        }
        self.blocked.insert(ip, (name, now));
        true
    }

    /// Writes the blocked addresses with their age, so the next netmond
    /// blocks them at once: a program that cached its DNS answer sends no
    /// new one. Returns an error message.
    pub(crate) fn save_blocked(&self, path: &std::path::Path, gid: Option<u32>, now: Instant) -> Option<String> {
        let unix = rules::unix_now();
        let list: Vec<(std::net::IpAddr, &str, u64)> = self
            .blocked
            .iter()
            .map(|(ip, (name, seen))| (*ip, name.as_str(), unix.saturating_sub(now.duration_since(*seen).as_secs())))
            .collect();
        let text = serde_json::to_string(&list).unwrap_or_default();
        crate::usage::write_private(path, text.as_bytes(), gid).err().map(|e| format!("blocked addresses {}: {e}", path.display()))
    }

    /// Reads the addresses that an earlier netmond saved, if they are not
    /// older than names::KEEP and a host pattern still blocks their name,
    /// and writes them to the kernel.
    pub(crate) fn load_blocked(&mut self, path: &std::path::Path, now: Instant) -> Option<String> {
        let text = std::fs::read_to_string(path).ok()?;
        let list: Vec<(std::net::IpAddr, String, u64)> = serde_json::from_str(&text).unwrap_or_default();
        let unix = rules::unix_now();
        for (ip, name, seen) in list {
            let age = std::time::Duration::from_secs(unix.saturating_sub(seen));
            if age < names::KEEP
                && self.rules.host_pattern_blocked(&name)
                && let Some(t) = now.checked_sub(age)
            {
                self.block_address(ip, name, t);
            }
        }
        self.sync_host_blocks(now)
    }
}
