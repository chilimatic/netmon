//! Hostnames from DNS answers and TLS SNI.

use super::*;

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
    pub(crate) fn poll_names(&mut self, now: Instant) -> bool {
        let mut learned: Vec<(std::net::IpAddr, String)> = Vec::new();
        let (hosts, sni, parts, dns) = (&mut self.hosts, &mut self.sni, &mut self.hello_parts, &mut self.dns_pending);
        let unix = rules::unix_now();
        self.probe.drain_names(NAME_BATCH, |ev| {
            let data = &ev.data[..(ev.len as usize).min(ev.data.len())];
            match ev.kind {
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
                                server: procmap::normalize(collector::addr(ev.key.family, &ev.key.remote_addr, 0)).ip(),
                                name: a.name,
                                qtype: names::qtype_text(a.qtype),
                                rcode: names::rcode_text(a.rcode),
                                answers: a.answers,
                                blocked: false,
                            },
                        ));
                    }
                    for (ip, name, _ttl) in names::dns_answers(data) {
                        learned.push((ip, name.clone()));
                        hosts.insert(ip, name, now);
                    }
                }
                netmon_common::NAME_TLS => match names::client_hello_sni(data) {
                    Some(name) => {
                        learned.push((collector::addr(ev.key.family, &ev.key.remote_addr, 0).ip(), name.clone()));
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
                            learned.push((collector::addr(ev.key.family, &ev.key.remote_addr, 0).ip(), name.clone()));
                            sni.insert(ev.key, name);
                        }
                    }
                }
                _ => {}
            }
        });
        let mut found = false;
        for (ip, name) in learned {
            if self.rules.host_blocked(&name) {
                let ip = procmap::normalize(std::net::SocketAddr::new(ip, 0)).ip();
                found |= self.blocked.insert(ip, (name, now)).is_none();
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
}
