//! Block rules held by netmon. They live in the kernel maps only while
//! netmon runs (fail-open: quitting or a crash removes every block).

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use netmon_common::{IPPROTO_TCP, IPPROTO_UDP, MAX_RULES};

use crate::procmap::normalize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockTarget {
    /// Remote network: address and prefix length.
    Net(IpAddr, u8),
    /// Remote port for one protocol.
    Port(u8, u16),
    /// Every process running this binary (absolute exe path).
    Exe(String),
}

impl BlockTarget {
    /// Single remote address.
    pub fn host(ip: IpAddr) -> Self {
        let ip = normalize(SocketAddr::new(ip, 0)).ip();
        BlockTarget::Net(ip, if ip.is_ipv4() { 32 } else { 128 })
    }

    /// Does traffic to `remote` with `proto` of a process running `exe`
    /// match?
    pub fn matches(&self, proto: u8, remote: SocketAddr, exe: &str) -> bool {
        let remote = normalize(remote);
        match self {
            BlockTarget::Net(net, len) => in_net(remote.ip(), *net, *len),
            BlockTarget::Port(p, port) => *p == proto && *port == remote.port(),
            BlockTarget::Exe(path) => !exe.is_empty() && path == exe,
        }
    }
}

impl fmt::Display for BlockTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BlockTarget::Net(ip, len) if *len == if ip.is_ipv4() { 32 } else { 128 } => write!(f, "host {ip}"),
            BlockTarget::Net(ip, len) => write!(f, "net {ip}/{len}"),
            BlockTarget::Port(p, port) => write!(f, "{} port {port}", proto_name(*p)),
            BlockTarget::Exe(path) => write!(f, "exe {path}"),
        }
    }
}

pub fn proto_name(p: u8) -> &'static str {
    match p {
        IPPROTO_TCP => "tcp",
        IPPROTO_UDP => "udp",
        _ => "ip",
    }
}

fn in_net(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = u32::MAX.checked_shl(32 - len as u32).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = u128::MAX.checked_shl(128 - len as u32).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Index into the kernel's per-rule drop counters.
    pub id: u32,
    pub target: BlockTarget,
    /// Packets dropped and socket calls denied.
    pub drops: u64,
}

#[derive(Default)]
pub struct Rules {
    pub rules: Vec<Rule>,
}

impl Rules {
    /// Adds a rule. Returns its id, or an error when it exists or the
    /// table is full.
    pub fn add(&mut self, target: BlockTarget) -> Result<u32, String> {
        if let BlockTarget::Exe(p) = &target
            && (!p.starts_with('/') || p.len() >= netmon_common::MAX_EXE_PATH)
        {
            return Err(format!("cannot block exe {p:?}: needs an absolute path under 256 bytes"));
        }
        if self.rules.iter().any(|r| r.target == target) {
            return Err(format!("{target} is already blocked"));
        }
        let id = (0..MAX_RULES)
            .find(|id| self.rules.iter().all(|r| r.id != *id))
            .ok_or_else(|| format!("rule limit {MAX_RULES} reached"))?;
        self.rules.push(Rule { id, target, drops: 0 });
        Ok(id)
    }

    pub fn remove(&mut self, id: u32) -> Option<Rule> {
        let i = self.rules.iter().position(|r| r.id == id)?;
        Some(self.rules.remove(i))
    }

    /// The first rule that blocks traffic to `remote` by a process running
    /// `exe` ("" if unknown).
    pub fn matching(&self, proto: u8, remote: SocketAddr, exe: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.target.matches(proto, remote, exe))
    }

    /// Exe path -> rule id of every process block.
    pub fn exes(&self) -> impl Iterator<Item = (&str, u32)> {
        self.rules.iter().filter_map(|r| match &r.target {
            BlockTarget::Exe(p) => Some((p.as_str(), r.id)),
            _ => None,
        })
    }

    /// The rule with exactly this target.
    pub fn find(&self, target: &BlockTarget) -> Option<&Rule> {
        self.rules.iter().find(|r| r.target == *target)
    }
}

/// Groups running processes by blocked exe: rule id -> pids.
pub fn pids_by_exe(running: impl Iterator<Item = (u32, String)>, exes: &[(String, u32)]) -> Vec<(u32, Vec<u32>)> {
    let mut out: Vec<(u32, Vec<u32>)> = exes.iter().map(|(_, id)| (*id, Vec::new())).collect();
    for (pid, exe) in running {
        if let Some(i) = exes.iter().position(|(p, _)| *p == exe) {
            out[i].1.push(pid);
        }
    }
    out.retain(|(_, pids)| !pids.is_empty());
    out
}

/// Endpoints that are never blocked: the SSH client of the session netmon
/// runs in, and the DNS servers in resolv.conf (port 53). Loopback is
/// guarded in the kernel by address.
pub fn guard_endpoints(ssh_connection: Option<&str>, resolv_conf: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    // "client_ip client_port server_ip server_port": the client is the
    // remote end of the session on this host.
    if let Some(s) = ssh_connection {
        let mut f = s.split_whitespace();
        if let (Some(ip), Some(port)) = (f.next(), f.next())
            && let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), port.parse::<u16>())
        {
            out.push(normalize(SocketAddr::new(ip, port)));
        }
    }
    for line in resolv_conf.lines() {
        let mut f = line.split_whitespace();
        if f.next() == Some("nameserver")
            && let Some(ip) = f.next()
            // Drop a zone id such as fe80::1%eth0.
            && let Ok(ip) = ip.split('%').next().unwrap_or("").parse::<IpAddr>()
        {
            out.push(normalize(SocketAddr::new(ip, 53)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn targets_match() {
        let host = BlockTarget::host("1.1.1.1".parse().unwrap());
        assert!(host.matches(IPPROTO_TCP, sa("1.1.1.1:443"), ""));
        assert!(host.matches(IPPROTO_UDP, sa("[::ffff:1.1.1.1]:53"), ""), "mapped v4");
        assert!(!host.matches(IPPROTO_TCP, sa("1.1.1.2:443"), ""));
        let net = BlockTarget::Net("10.0.0.0".parse().unwrap(), 8);
        assert!(net.matches(IPPROTO_TCP, sa("10.200.3.4:1"), ""));
        assert!(!net.matches(IPPROTO_TCP, sa("11.0.0.1:1"), ""));
        let v6 = BlockTarget::Net("2001:db8::".parse().unwrap(), 32);
        assert!(v6.matches(IPPROTO_TCP, sa("[2001:db8:1::5]:80"), ""));
        assert!(!v6.matches(IPPROTO_TCP, sa("1.1.1.1:80"), ""));
        let all = BlockTarget::Net("0.0.0.0".parse().unwrap(), 0);
        assert!(all.matches(IPPROTO_TCP, sa("8.8.8.8:1"), ""));
        let port = BlockTarget::Port(IPPROTO_TCP, 25);
        assert!(port.matches(IPPROTO_TCP, sa("9.9.9.9:25"), ""));
        assert!(!port.matches(IPPROTO_UDP, sa("9.9.9.9:25"), ""));
    }

    #[test]
    fn display() {
        assert_eq!(BlockTarget::host("1.1.1.1".parse().unwrap()).to_string(), "host 1.1.1.1");
        assert_eq!(BlockTarget::Net("10.0.0.0".parse().unwrap(), 8).to_string(), "net 10.0.0.0/8");
        assert_eq!(BlockTarget::Port(IPPROTO_UDP, 53).to_string(), "udp port 53");
    }

    #[test]
    fn ids_are_reused_and_duplicates_refused() {
        let mut r = Rules::default();
        let a = r.add(BlockTarget::Port(IPPROTO_TCP, 1)).unwrap();
        let b = r.add(BlockTarget::Port(IPPROTO_TCP, 2)).unwrap();
        assert_eq!((a, b), (0, 1));
        assert!(r.add(BlockTarget::Port(IPPROTO_TCP, 1)).is_err());
        r.remove(a).unwrap();
        assert_eq!(r.add(BlockTarget::Port(IPPROTO_TCP, 3)).unwrap(), 0, "free id reused");
        assert_eq!(r.matching(IPPROTO_TCP, sa("1.2.3.4:2"), "").unwrap().id, 1);
    }

    #[test]
    fn rule_limit() {
        let mut r = Rules::default();
        for p in 0..MAX_RULES {
            r.add(BlockTarget::Port(IPPROTO_UDP, p as u16)).unwrap();
        }
        assert!(r.add(BlockTarget::Port(IPPROTO_TCP, 1)).unwrap_err().contains("limit"));
    }

    #[test]
    fn guard_from_ssh_and_resolv_conf() {
        let g = guard_endpoints(
            Some("192.168.1.20 51234 192.168.1.5 22"),
            "# comment\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\noptions edns0\nsearch lan\n",
        );
        assert_eq!(g, vec![sa("192.168.1.20:51234"), sa("127.0.0.53:53"), sa("[fe80::1]:53")]);
        assert!(guard_endpoints(Some("garbage"), "").is_empty());
    }

    #[test]
    fn exe_targets() {
        let mut r = Rules::default();
        let id = r.add(BlockTarget::Exe("/usr/bin/curl".into())).unwrap();
        assert_eq!(r.matching(IPPROTO_TCP, sa("1.1.1.1:443"), "/usr/bin/curl").unwrap().id, id);
        assert!(r.matching(IPPROTO_TCP, sa("1.1.1.1:443"), "/usr/bin/wget").is_none());
        assert!(r.matching(IPPROTO_TCP, sa("1.1.1.1:443"), "").is_none());
        assert_eq!(r.exes().collect::<Vec<_>>(), vec![("/usr/bin/curl", id)]);
        assert_eq!(r.rules[0].target.to_string(), "exe /usr/bin/curl");
        assert!(r.add(BlockTarget::Exe("curl".into())).is_err(), "relative path");
        assert!(r.add(BlockTarget::Exe(format!("/{}", "a".repeat(300)))).is_err(), "too long");
    }

    #[test]
    fn running_processes_grouped_by_exe() {
        let exes = vec![("/usr/bin/curl".to_string(), 3), ("/usr/bin/wget".to_string(), 4)];
        let running = [(10, "/usr/bin/curl"), (11, "/usr/bin/bash"), (12, "/usr/bin/curl")];
        let got = pids_by_exe(running.iter().map(|(p, e)| (*p, e.to_string())), &exes);
        assert_eq!(got, vec![(3, vec![10, 12])]);
    }
}

