//! New listeners: a program binds a port that other hosts can reach. The
//! kernel's post_bind hooks record each bound socket (LISTENERS). The first
//! read after the start is the baseline: only binds after it are new.

use std::{collections::HashSet, net::SocketAddr};

use crate::procmap::{Owner, normalize};

/// Programs, protocols and ports remembered at most. When full, the set
/// starts again from the next read, without alerts for that read.
const MAX_SEEN: usize = 4096;

/// A bound socket that other hosts can reach, new since the start.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NewListener {
    pub proto: u8,
    pub addr: SocketAddr,
    pub pid: u32,
    pub comm: String,
    /// Empty if the process was gone before netmon could read it.
    pub exe: String,
}

/// One line: "new listener: python3 (pid 7, /usr/bin/python3.14) on tcp 0.0.0.0:8000".
pub fn describe(l: &NewListener) -> String {
    let exe = if l.exe.is_empty() { String::new() } else { format!(", {}", l.exe) };
    format!("new listener: {} (pid {}{exe}) on {} {}", l.comm, l.pid, crate::rules::proto_name(l.proto), l.addr)
}

pub(crate) struct ListenWatch {
    /// (protocol, port, process name) already reported or in the baseline.
    seen: HashSet<(u8, u16, String)>,
    baseline: bool,
    /// UDP ports in this range are client sockets (DNS lookups, WebRTC).
    ephemeral: (u16, u16),
}

impl Default for ListenWatch {
    fn default() -> Self {
        ListenWatch { seen: HashSet::new(), baseline: false, ephemeral: ephemeral_range() }
    }
}

impl ListenWatch {
    /// The new entries of `entries` that other hosts can reach. Each
    /// program, protocol and port is reported once.
    pub(crate) fn check(&mut self, entries: &[(u8, SocketAddr, Owner)]) -> Vec<(u8, SocketAddr, Owner)> {
        if self.seen.len() >= MAX_SEEN {
            self.seen.clear();
            self.baseline = false;
        }
        let mut out = Vec::new();
        for (proto, addr, owner) in entries {
            let addr = normalize(*addr);
            if !self.reachable(*proto, addr) {
                continue;
            }
            if self.seen.insert((*proto, addr.port(), owner.comm.clone())) && self.baseline {
                out.push((*proto, addr, owner.clone()));
            }
        }
        self.baseline = true;
        out
    }

    fn reachable(&self, proto: u8, addr: SocketAddr) -> bool {
        let ip = addr.ip();
        if ip.is_loopback() || ip.is_multicast() || addr.port() == 0 {
            return false;
        }
        let (lo, hi) = self.ephemeral;
        !(proto == netmon_common::IPPROTO_UDP && (lo..=hi).contains(&addr.port()))
    }
}

/// The kernel's ephemeral port range, 32768-60999 if it cannot be read.
fn ephemeral_range() -> (u16, u16) {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|s| {
            let mut it = s.split_whitespace().map(|p| p.parse::<u16>().ok());
            Some((it.next()??, it.next()??))
        })
        .unwrap_or((32768, 60999))
}

#[cfg(test)]
mod tests {
    use super::*;
    use netmon_common::{IPPROTO_TCP, IPPROTO_UDP};

    fn owner(comm: &str) -> Owner {
        Owner { pid: 7, comm: comm.into(), uid: Some(0), details: None, container: None }
    }

    fn e(proto: u8, a: &str, comm: &str) -> (u8, SocketAddr, Owner) {
        (proto, a.parse().unwrap(), owner(comm))
    }

    #[test]
    fn reports_new_reachable_binds_once() {
        let mut w = ListenWatch { ephemeral: (32768, 60999), ..ListenWatch::default() };
        let base = vec![e(IPPROTO_TCP, "0.0.0.0:22", "sshd")];
        assert!(w.check(&base).is_empty(), "baseline");
        let mut now = base.clone();
        now.extend([
            e(IPPROTO_TCP, "0.0.0.0:8000", "python3"),
            e(IPPROTO_TCP, "127.0.0.1:9000", "python3"),
            e(IPPROTO_TCP, "[::1]:9001", "python3"),
            e(IPPROTO_UDP, "0.0.0.0:40000", "firefox"),
            e(IPPROTO_UDP, "224.0.0.251:5353", "avahi"),
            e(IPPROTO_UDP, "[::ffff:192.168.1.5]:5000", "app"),
        ]);
        let got: Vec<_> = w.check(&now).into_iter().map(|(p, a, o)| (p, a.to_string(), o.comm)).collect();
        assert_eq!(
            got,
            vec![(IPPROTO_TCP, "0.0.0.0:8000".into(), "python3".into()), (IPPROTO_UDP, "192.168.1.5:5000".into(), "app".into())]
        );
        assert!(w.check(&now).is_empty(), "once");
        // The same port of another program is new.
        now.push(e(IPPROTO_TCP, "[::]:8000", "node"));
        assert_eq!(w.check(&now).len(), 1);
    }
}
