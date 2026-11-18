//! Maps sockets to the owning process with /proc.
//! Reads /proc/net/{tcp,tcp6,udp,udp6} for socket inodes, then
//! /proc/<pid>/fd for which process holds each inode.
//! Only sockets in this process's network namespace are visible.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use netmon_common::{IPPROTO_TCP, IPPROTO_UDP};
use procfs::{
    net::TcpState,
    process::{FDTarget, all_processes},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    pub comm: String,
}

#[derive(Clone, Debug)]
pub struct SockInfo {
    pub owner: Option<Owner>,
    pub state: &'static str,
}

#[derive(Clone, Debug)]
pub struct RawSock {
    pub proto: u8,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: &'static str,
    pub inode: u64,
}

/// Socket lookup by exact 4-tuple, with a fallback by local port for
/// listeners and unconnected UDP sockets.
#[derive(Default)]
pub struct SocketTable {
    exact: HashMap<(u8, SocketAddr, SocketAddr), SockInfo>,
    by_port: HashMap<(u8, u16), SockInfo>,
}

impl SocketTable {
    pub fn build(socks: Vec<RawSock>, owners: &HashMap<u64, Owner>) -> Self {
        let mut t = SocketTable::default();
        for s in socks {
            let info = SockInfo {
                owner: owners.get(&s.inode).cloned(),
                state: s.state,
            };
            let local = normalize(s.local);
            let remote = normalize(s.remote);
            let unbound_peer = remote.port() == 0;
            // Prefer listeners and unconnected sockets for the port fallback.
            if unbound_peer || !t.by_port.contains_key(&(s.proto, local.port())) {
                t.by_port.insert((s.proto, local.port()), info.clone());
            }
            if !unbound_peer {
                t.exact.insert((s.proto, local, remote), info);
            }
        }
        t
    }

    pub fn lookup(&self, proto: u8, local: SocketAddr, remote: SocketAddr) -> Option<&SockInfo> {
        let (local, remote) = (normalize(local), normalize(remote));
        self.exact
            .get(&(proto, local, remote))
            .or_else(|| self.by_port.get(&(proto, local.port())))
    }

    /// Reads the current socket table and owners from /proc.
    pub fn read() -> Self {
        Self::build(read_sockets(), &read_owners())
    }
}

/// Turns IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) into plain IPv4.
pub fn normalize(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => a,
        },
        IpAddr::V4(_) => a,
    }
}

fn tcp_state(s: &TcpState) -> &'static str {
    match s {
        TcpState::Established => "ESTAB",
        TcpState::SynSent => "SYN-SENT",
        TcpState::SynRecv | TcpState::NewSynRecv => "SYN-RECV",
        TcpState::FinWait1 => "FIN-WAIT-1",
        TcpState::FinWait2 => "FIN-WAIT-2",
        TcpState::TimeWait => "TIME-WAIT",
        TcpState::Close => "CLOSE",
        TcpState::CloseWait => "CLOSE-WAIT",
        TcpState::LastAck => "LAST-ACK",
        TcpState::Listen => "LISTEN",
        TcpState::Closing => "CLOSING",
    }
}

fn read_sockets() -> Vec<RawSock> {
    let mut out = Vec::new();
    for tcp in [procfs::net::tcp(), procfs::net::tcp6()].into_iter().flatten() {
        out.extend(tcp.into_iter().map(|e| RawSock {
            proto: IPPROTO_TCP,
            local: e.local_address,
            remote: e.remote_address,
            state: tcp_state(&e.state),
            inode: e.inode,
        }));
    }
    for udp in [procfs::net::udp(), procfs::net::udp6()].into_iter().flatten() {
        out.extend(udp.into_iter().map(|e| RawSock {
            proto: IPPROTO_UDP,
            local: e.local_address,
            remote: e.remote_address,
            state: "",
            inode: e.inode,
        }));
    }
    out
}

/// Socket inode -> owning process. Processes we may not inspect are skipped.
fn read_owners() -> HashMap<u64, Owner> {
    let mut owners = HashMap::new();
    let Ok(procs) = all_processes() else {
        return owners;
    };
    for p in procs.flatten() {
        let Ok(fds) = p.fd() else { continue };
        let mut comm = None;
        for fd in fds.flatten() {
            if let FDTarget::Socket(inode) = fd.target {
                let comm = comm.get_or_insert_with(|| {
                    p.stat().map(|s| s.comm).unwrap_or_else(|_| "?".into())
                });
                owners.entry(inode).or_insert_with(|| Owner {
                    pid: p.pid as u32,
                    comm: comm.clone(),
                });
            }
        }
    }
    owners
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn owners() -> HashMap<u64, Owner> {
        HashMap::from([
            (1, Owner { pid: 10, comm: "curl".into() }),
            (2, Owner { pid: 20, comm: "nginx".into() }),
            (3, Owner { pid: 30, comm: "dig".into() }),
        ])
    }

    fn table() -> SocketTable {
        SocketTable::build(
            vec![
                RawSock { proto: IPPROTO_TCP, local: sa("10.0.0.2:40000"), remote: sa("1.1.1.1:443"), state: "ESTAB", inode: 1 },
                RawSock { proto: IPPROTO_TCP, local: sa("[::]:80"), remote: sa("[::]:0"), state: "LISTEN", inode: 2 },
                RawSock { proto: IPPROTO_UDP, local: sa("0.0.0.0:5353"), remote: sa("0.0.0.0:0"), state: "", inode: 3 },
            ],
            &owners(),
        )
    }

    #[test]
    fn exact_match() {
        let t = table();
        let i = t.lookup(IPPROTO_TCP, sa("10.0.0.2:40000"), sa("1.1.1.1:443")).unwrap();
        assert_eq!(i.owner.as_ref().unwrap().comm, "curl");
        assert_eq!(i.state, "ESTAB");
    }

    #[test]
    fn falls_back_to_listener_port() {
        let t = table();
        let i = t.lookup(IPPROTO_TCP, sa("10.0.0.2:80"), sa("9.9.9.9:5555")).unwrap();
        assert_eq!(i.owner.as_ref().unwrap().pid, 20);
    }

    #[test]
    fn unconnected_udp_by_port() {
        let t = table();
        let i = t.lookup(IPPROTO_UDP, sa("10.0.0.2:5353"), sa("224.0.0.251:5353")).unwrap();
        assert_eq!(i.owner.as_ref().unwrap().comm, "dig");
    }

    #[test]
    fn mapped_v6_matches_v4() {
        let t = SocketTable::build(
            vec![RawSock { proto: IPPROTO_TCP, local: sa("[::ffff:10.0.0.2]:8080"), remote: sa("[::ffff:10.0.0.9]:5000"), state: "ESTAB", inode: 2 }],
            &owners(),
        );
        assert!(t.lookup(IPPROTO_TCP, sa("10.0.0.2:8080"), sa("10.0.0.9:5000")).is_some());
    }

    #[test]
    fn unknown_is_none() {
        assert!(table().lookup(IPPROTO_TCP, sa("10.0.0.2:1"), sa("1.1.1.1:2")).is_none());
    }
}
