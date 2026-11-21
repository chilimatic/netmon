//! Hostnames from DNS answers and TLS SNI.

use super::*;

impl<K: Kernel> Monitor<K> {
    /// Reads new DNS answers and ClientHellos and names every flow's
    /// remote end. The TLS server name wins: it is what the client asked
    /// this server for, while one address can serve many DNS names.
    pub(crate) fn refresh_hosts(&mut self, now: Instant) {
        let (hosts, sni, parts) = (&mut self.hosts, &mut self.sni, &mut self.hello_parts);
        self.probe.drain_names(NAME_BATCH, |ev| {
            let data = &ev.data[..(ev.len as usize).min(ev.data.len())];
            match ev.kind {
                netmon_common::NAME_DNS => {
                    for (ip, name, _ttl) in names::dns_answers(data) {
                        hosts.insert(ip, name, now);
                    }
                }
                netmon_common::NAME_TLS => match names::client_hello_sni(data) {
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
}
