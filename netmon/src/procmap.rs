//! Maps sockets to the owning process with /proc.
//! Reads /proc/net/{tcp,tcp6,udp,udp6} for socket inodes, then
//! /proc/<pid>/fd for which process holds each inode.
//! Sockets of other network namespaces (containers) come from
//! /proc/<pid>/net/* of a process in that namespace.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::Path,
};

use netmon_common::{COMM_LEN, ConnKey, DIR_IN, DIR_OUT, IPPROTO_TCP, IPPROTO_UDP, ListenKey, SockOwner};
use procfs::{
    net::TcpState,
    process::{FDTarget, all_processes},
};

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Owner {
    pub pid: u32,
    /// Task name. Any process can change its own; never proof of identity.
    pub comm: String,
    pub uid: Option<u32>,
    /// Set by `ProcCache::fill`. None until then, or when unreadable
    /// (process gone, kernel thread).
    pub details: Option<ProcDetails>,
    /// Container (network namespace) the socket lives in, if not netmon's.
    pub container: Option<String>,
}

/// Facts about a process that the process itself cannot fake.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProcDetails {
    /// Path of the running binary, from /proc/<pid>/exe.
    pub exe: String,
    /// User name for the uid, or the uid as a number.
    pub user: String,
    /// systemd unit or scope from the cgroup path, e.g. `sshd.service`.
    pub unit: String,
    /// Full cgroup v2 path.
    pub cgroup: String,
}

impl Owner {
    pub fn new(pid: u32, comm: &str) -> Self {
        Owner { pid, comm: comm.into(), ..Default::default() }
    }

    /// Owner recorded by the kernel hooks.
    pub fn from_kernel(o: &netmon_common::SockOwner) -> Self {
        let end = o.comm.iter().position(|b| *b == 0).unwrap_or(o.comm.len());
        Owner {
            pid: o.tgid,
            comm: crate::text::sanitize(&String::from_utf8_lossy(&o.comm[..end])),
            uid: Some(o.uid),
            details: None,
            container: None,
        }
    }
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
/// listeners and unconnected UDP sockets. The fallback also needs the bound
/// address to match the flow's local address, or to be a wildcard. Without
/// that, traffic of a container to 8.8.8.8:53 would be given to the
/// resolver bound to 127.0.0.53:53.
#[derive(Default)]
pub struct SocketTable {
    exact: HashMap<(u8, SocketAddr, SocketAddr), SockInfo>,
    by_port: HashMap<(u8, u16), Vec<Bound>>,
}

#[derive(Clone, Debug)]
struct Bound {
    ip: IpAddr,
    /// Listener or unconnected socket (no peer).
    unconnected: bool,
    info: SockInfo,
}

impl Bound {
    /// Lower is better: exact address before wildcard, unconnected before
    /// connected. None when the socket cannot receive for `ip`.
    fn rank(&self, ip: IpAddr) -> Option<u8> {
        Some(bind_rank(self.ip, ip)? + u8::from(!self.unconnected))
    }
}

/// How well a socket bound to `bound` matches traffic to local `ip`:
/// 0 exact address, 2 wildcard, None no match. [::] also takes IPv4 on
/// dual-stack sockets; 0.0.0.0 only IPv4.
fn bind_rank(bound: IpAddr, ip: IpAddr) -> Option<u8> {
    if bound == ip {
        Some(0)
    } else if bound.is_unspecified() && (bound.is_ipv6() || ip.is_ipv4()) {
        Some(2)
    } else {
        None
    }
}

/// Bound sockets recorded by the kernel post_bind hooks.
#[derive(Default)]
pub struct Listeners {
    by_port: HashMap<(u8, u16), Vec<(IpAddr, Owner)>>,
}

impl Listeners {
    pub fn build(entries: impl IntoIterator<Item = (u8, SocketAddr, Owner)>) -> Self {
        let mut l = Listeners::default();
        for (proto, addr, owner) in entries {
            let addr = normalize(addr);
            l.by_port.entry((proto, addr.port())).or_default().push((addr.ip(), owner));
        }
        l
    }

    /// Owner of the socket bound to the flow's local address, exact
    /// address before wildcard.
    pub fn lookup(&self, proto: u8, local: SocketAddr) -> Option<&Owner> {
        let local = normalize(local);
        self.by_port
            .get(&(proto, local.port()))?
            .iter()
            .filter_map(|(ip, o)| bind_rank(*ip, local.ip()).map(|r| (r, o)))
            .min_by_key(|(r, _)| *r)
            .map(|(_, o)| o)
    }
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
            let unconnected = remote.port() == 0;
            t.by_port.entry((s.proto, local.port())).or_default().push(Bound {
                ip: local.ip(),
                unconnected,
                info: info.clone(),
            });
            if !unconnected {
                t.exact.insert((s.proto, local, remote), info);
            }
        }
        t
    }

    #[cfg(test)]
    pub fn lookup(&self, proto: u8, local: SocketAddr, remote: SocketAddr) -> Option<&SockInfo> {
        self.lookup_kind(proto, local, remote).map(|(i, _)| i)
    }

    /// Like `lookup`, and tells whether the match was the exact 4-tuple
    /// (true) or the port fallback (false).
    pub fn lookup_kind(&self, proto: u8, local: SocketAddr, remote: SocketAddr) -> Option<(&SockInfo, bool)> {
        let (local, remote) = (normalize(local), normalize(remote));
        if let Some(i) = self.exact.get(&(proto, local, remote)) {
            return Some((i, true));
        }
        self.by_port
            .get(&(proto, local.port()))?
            .iter()
            .filter_map(|b| b.rank(local.ip()).map(|r| (r, &b.info)))
            .min_by_key(|(r, _)| *r)
            .map(|(_, i)| (i, false))
    }

    /// Reads the current socket table from /proc. Owners come from the
    /// cache, which scans /proc/*/fd only for sockets `wanted` asks for
    /// and it has not seen.
    pub fn read(cache: &mut OwnerCache, wanted: impl Fn(&RawSock) -> bool) -> Self {
        let socks = read_sockets(None);
        let inodes: HashSet<u64> = socks.iter().map(|s| s.inode).collect();
        let want: HashSet<u64> = socks.iter().filter(|s| wanted(s)).map(|s| s.inode).collect();
        cache.refresh_wanted(&inodes, &want, |pid| Path::new(&format!("/proc/{pid}")).exists(), || read_owners(None));
        Self::build(socks, &cache.owners)
    }
}

/// Reads the socket tables of other network namespaces (containers). Costly
/// (each UDP table read walks the kernel's whole UDP hash table: ~5 ms per
/// namespace), so callers read them only when needed. `cache` is kept apart
/// from the host's: the /proc/*/fd scan behind it covers container
/// processes too.
pub fn read_containers(cache: &mut OwnerCache, namespaces: &[crate::netns::Netns]) -> Vec<ContainerTable> {
    let foreign: Vec<(String, Vec<RawSock>)> = namespaces
        .iter()
        .filter_map(|n| {
            let p = procfs::process::Process::new(n.pid as i32).ok()?;
            Some((n.name.clone(), read_sockets(Some(&p))))
        })
        .collect();
    let inodes: HashSet<u64> = foreign.iter().flat_map(|(_, s)| s).map(|s| s.inode).collect();
    // Only processes in these namespaces can own their sockets.
    let pids: Vec<u32> = namespaces.iter().flat_map(|n| n.pids.iter().copied()).collect();
    cache.refresh(&inodes, |pid| Path::new(&format!("/proc/{pid}")).exists(), || read_owners(Some(&pids)));
    foreign.into_iter().map(|(name, socks)| ContainerTable::build(&name, socks, &cache.owners)).collect()
}

/// Sockets of one container's network namespace. Its flows are seen on the
/// host from outside: on veth and bridge interfaces the container is the
/// remote end; on the uplink, after masquerade, the local address is the
/// host's but the remote end and (usually) the local port are the
/// container socket's.
#[derive(Default)]
pub struct ContainerTable {
    exact: HashMap<(u8, SocketAddr, SocketAddr), Owner>,
    by_remote: HashMap<(u8, SocketAddr, u16), Owner>,
}

impl ContainerTable {
    pub fn build(name: &str, socks: Vec<RawSock>, owners: &HashMap<u64, Owner>) -> Self {
        let mut t = ContainerTable::default();
        for s in socks {
            let Some(o) = owners.get(&s.inode) else { continue };
            let o = Owner { container: Some(name.to_string()), ..o.clone() };
            let (local, remote) = (normalize(s.local), normalize(s.remote));
            if remote.port() == 0 {
                continue;
            }
            t.by_remote.insert((s.proto, remote, local.port()), o.clone());
            t.exact.insert((s.proto, local, remote), o);
        }
        t
    }

    /// The container process behind a flow seen on the host with these
    /// local and remote ends. True if the match is exact (veth, bridge),
    /// false if it is by remote end and port (uplink after NAT).
    pub fn lookup(&self, proto: u8, local: SocketAddr, remote: SocketAddr) -> Option<(&Owner, bool)> {
        let (local, remote) = (normalize(local), normalize(remote));
        if let Some(o) = self.exact.get(&(proto, remote, local)) {
            return Some((o, true));
        }
        self.by_remote.get(&(proto, remote, local.port())).map(|o| (o, false))
    }
}

/// Socket inode -> owner, kept across ticks. A full scan of /proc/*/fd
/// costs one readlink per open file on the host, so it runs only when a
/// socket inode shows up that is neither known nor already failed.
#[derive(Default)]
pub struct OwnerCache {
    owners: HashMap<u64, Owner>,
    /// Inodes a scan could not find an owner for (kernel sockets, other
    /// namespaces). Tried again with the next scan.
    misses: HashSet<u64>,
    pub scans: u64,
    /// Shortest time between two scans. A scan reads every fd of every
    /// process: 150 ms on a host with 3600 processes.
    pub min_gap: std::time::Duration,
    last_scan: Option<std::time::Instant>,
}

impl OwnerCache {
    /// Keeps entries for live sockets of live processes. Scans when an
    /// inode is new. Inode 0 (TIME-WAIT, no file) never has an owner.
    pub fn refresh(
        &mut self,
        inodes: &HashSet<u64>,
        alive: impl Fn(u32) -> bool,
        scan: impl FnOnce() -> HashMap<u64, Owner>,
    ) {
        self.refresh_wanted(inodes, inodes, alive, scan);
    }

    /// Like `refresh`, but only a new inode in `wanted` (a subset of
    /// `inodes`) starts a scan: sockets whose owner nobody needs never do.
    pub fn refresh_wanted(
        &mut self,
        inodes: &HashSet<u64>,
        wanted: &HashSet<u64>,
        alive: impl Fn(u32) -> bool,
        scan: impl FnOnce() -> HashMap<u64, Owner>,
    ) {
        // A process that exits can leave its socket to a child (fork, then
        // exit). Drop the dead owner so the next scan finds the new one.
        let mut live: HashMap<u32, bool> = HashMap::new();
        self.owners
            .retain(|i, o| inodes.contains(i) && *live.entry(o.pid).or_insert_with(|| alive(o.pid)));
        self.misses.retain(|i| inodes.contains(i));
        let new = wanted.iter().any(|i| *i != 0 && !self.owners.contains_key(i) && !self.misses.contains(i));
        if !new || self.last_scan.is_some_and(|t| t.elapsed() < self.min_gap) {
            return;
        }
        let found = scan();
        self.scans += 1;
        self.last_scan = Some(std::time::Instant::now());
        for &i in inodes.iter().filter(|i| **i != 0) {
            match found.get(&i) {
                Some(o) => {
                    self.owners.insert(i, o.clone());
                    self.misses.remove(&i);
                }
                None => {
                    self.misses.insert(i);
                }
            }
        }
    }
}

/// Every socket of netmon's namespace with its owner, from one full
/// /proc scan. Sockets with no owner found are left out.
pub fn sockets_with_owners() -> Vec<(RawSock, Owner)> {
    let owners = read_owners(None);
    read_sockets(None).into_iter().filter_map(|s| owners.get(&s.inode).map(|o| (s, o.clone()))).collect()
}

/// A connection key, its direction (DIR_*) and the owner tgid.
pub type SeedConn = (ConnKey, u8, u32);

/// Kernel entries for sockets that existed before the start, for
/// `Kernel::seed`: connections with direction and owner tgid, and bound
/// sockets. A connection is inbound when a bound socket of its protocol
/// takes its local address and port.
pub fn seed_entries(socks: &[(RawSock, Owner)]) -> (Vec<SeedConn>, Vec<(ListenKey, SockOwner)>) {
    let unconnected = |s: &RawSock| if s.proto == IPPROTO_TCP { s.state == "LISTEN" } else { s.remote.port() == 0 };
    let mut listeners = Vec::new();
    let mut bound = Vec::new();
    for (s, o) in socks.iter().filter(|(s, _)| unconnected(s)) {
        // The kernel keys bound sockets by the raw address, mapped
        // IPv6 addresses as IPv6.
        let (family, addr) = crate::rules::addr_bytes(s.local.ip());
        listeners.push((ListenKey { addr, port: s.local.port(), proto: s.proto, family }, sock_owner(o)));
        bound.push((s.proto, normalize(s.local)));
    }
    let conns = socks
        .iter()
        .filter(|(s, _)| !unconnected(s) && s.remote.port() != 0)
        .map(|(s, o)| {
            let local = normalize(s.local);
            let remote = normalize(s.remote);
            let inbound = bound
                .iter()
                .any(|(p, b)| *p == s.proto && b.port() == local.port() && bind_rank(b.ip(), local.ip()).is_some());
            let (family, remote_addr) = crate::rules::addr_bytes(remote.ip());
            let key =
                ConnKey { remote_addr, local_port: local.port(), remote_port: remote.port(), family, proto: s.proto, _pad: [0; 2] };
            (key, if inbound { DIR_IN } else { DIR_OUT }, o.pid)
        })
        .collect();
    (conns, listeners)
}

fn sock_owner(o: &Owner) -> SockOwner {
    let mut comm = [0u8; COMM_LEN];
    let n = o.comm.len().min(COMM_LEN - 1);
    comm[..n].copy_from_slice(&o.comm.as_bytes()[..n]);
    SockOwner { tgid: o.pid, uid: o.uid.unwrap_or(0), cgroup_id: 0, comm }
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

/// Exe, user and unit per pid, read once per process. Entries of exited
/// processes are dropped, so a reused pid is read again.
#[derive(Default)]
pub struct ProcCache {
    by_pid: HashMap<u32, Option<ProcDetails>>,
    users: Option<HashMap<u32, String>>,
}

impl ProcCache {
    /// Forgets processes that are gone.
    pub fn prune(&mut self, alive: impl Fn(u32) -> bool) {
        self.by_pid.retain(|pid, _| alive(*pid));
    }

    /// Fills `owner.details` (and `uid` if unknown) from the cache, reading
    /// /proc on the first sight of a pid.
    pub fn fill(&mut self, owner: &mut Owner, read: impl FnOnce(u32) -> Option<RawDetails>) {
        if owner.details.is_some() {
            return;
        }
        let users = self.users.get_or_insert_with(read_users);
        let entry = self.by_pid.entry(owner.pid).or_insert_with(|| {
            read(owner.pid).map(|r| ProcDetails {
                user: users.get(&r.uid).cloned().unwrap_or_else(|| r.uid.to_string()),
                unit: unit_of(&r.cgroup).to_string(),
                exe: crate::text::sanitize(&r.exe),
                cgroup: crate::text::sanitize(&r.cgroup),
            })
        });
        owner.details = entry.clone();
    }
}

/// What /proc says about a process, before formatting.
pub struct RawDetails {
    pub exe: String,
    pub uid: u32,
    pub cgroup: String,
}

/// Reads exe, owner uid and cgroup v2 path of a process.
pub fn read_details(pid: u32) -> Option<RawDetails> {
    use std::os::unix::fs::MetadataExt;
    let dir = Path::new("/proc").join(pid.to_string());
    let uid = std::fs::metadata(&dir).ok()?.uid();
    // Kernel threads have no exe; keep them with an empty path.
    let exe = std::fs::read_link(dir.join("exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let cgroup = std::fs::read_to_string(dir.join("cgroup")).unwrap_or_default();
    let cgroup = cgroup.lines().find_map(|l| l.strip_prefix("0::")).unwrap_or("").to_string();
    Some(RawDetails { exe, uid, cgroup })
}

/// The most specific systemd unit or scope in a cgroup path:
/// `/user.slice/user-1000.slice/app.slice/app-firefox-1.scope` gives
/// `app-firefox-1.scope`. Falls back to the last path component.
pub fn unit_of(cgroup: &str) -> &str {
    let mut parts = cgroup.split('/').filter(|p| !p.is_empty()).rev();
    let last = parts.clone().next().unwrap_or("");
    parts.find(|p| p.ends_with(".service") || p.ends_with(".scope")).unwrap_or(last)
}

/// uid -> user name from /etc/passwd.
fn read_users() -> HashMap<u32, String> {
    let text = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            let name = f.next()?;
            let uid = f.nth(1)?.parse().ok()?;
            Some((uid, crate::text::sanitize(name)))
        })
        .collect()
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

/// Sockets of netmon's network namespace (`None`) or of the namespace
/// process `p` is in.
fn read_sockets(p: Option<&procfs::process::Process>) -> Vec<RawSock> {
    let mut out = Vec::new();
    let (tcp, tcp6, udp, udp6) = match p {
        Some(p) => (p.tcp(), p.tcp6(), p.udp(), p.udp6()),
        None => (procfs::net::tcp(), procfs::net::tcp6(), procfs::net::udp(), procfs::net::udp6()),
    };
    for tcp in [tcp, tcp6].into_iter().flatten() {
        out.extend(tcp.into_iter().map(|e| RawSock {
            proto: IPPROTO_TCP,
            local: e.local_address,
            remote: e.remote_address,
            state: tcp_state(&e.state),
            inode: e.inode,
        }));
    }
    for udp in [udp, udp6].into_iter().flatten() {
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

/// Socket inode -> owning process, from all processes or only `pids`.
/// Processes we may not inspect are skipped.
fn read_owners(pids: Option<&[u32]>) -> HashMap<u64, Owner> {
    let mut owners = HashMap::new();
    let procs: Vec<procfs::process::Process> = match pids {
        Some(pids) => pids.iter().filter_map(|p| procfs::process::Process::new(*p as i32).ok()).collect(),
        None => match all_processes() {
            Ok(all) => all.flatten().collect(),
            Err(_) => return owners,
        },
    };
    for p in procs {
        let Ok(fds) = p.fd() else { continue };
        let mut comm = None;
        for fd in fds.flatten() {
            if let FDTarget::Socket(inode) = fd.target {
                let comm = comm.get_or_insert_with(|| {
                    p.stat().map(|s| crate::text::sanitize(&s.comm)).unwrap_or_else(|_| "?".into())
                });
                owners.entry(inode).or_insert_with(|| Owner::new(p.pid as u32, comm));
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
            (1, Owner::new(10, "curl")),
            (2, Owner::new(20, "nginx")),
            (3, Owner::new(30, "dig")),
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

    #[test]
    fn port_fallback_needs_matching_address() {
        let t = SocketTable::build(
            vec![RawSock { proto: IPPROTO_UDP, local: sa("127.0.0.53:53"), remote: sa("0.0.0.0:0"), state: "", inode: 3 }],
            &owners(),
        );
        // Container DNS seen on a bridge: local is the remote resolver.
        assert!(t.lookup(IPPROTO_UDP, sa("8.8.8.8:53"), sa("172.17.0.2:40000")).is_none());
        assert!(t.lookup(IPPROTO_UDP, sa("127.0.0.53:53"), sa("127.0.0.1:40000")).is_some());
    }

    #[test]
    fn v4_wildcard_does_not_take_v6() {
        assert!(table().lookup(IPPROTO_UDP, sa("[fe80::1]:5353"), sa("[ff02::fb]:5353")).is_none());
    }

    #[test]
    fn exact_bind_beats_wildcard() {
        let t = SocketTable::build(
            vec![
                RawSock { proto: IPPROTO_TCP, local: sa("0.0.0.0:80"), remote: sa("0.0.0.0:0"), state: "LISTEN", inode: 2 },
                RawSock { proto: IPPROTO_TCP, local: sa("10.0.0.2:80"), remote: sa("0.0.0.0:0"), state: "LISTEN", inode: 1 },
            ],
            &owners(),
        );
        let i = t.lookup(IPPROTO_TCP, sa("10.0.0.2:80"), sa("9.9.9.9:1")).unwrap();
        assert_eq!(i.owner.as_ref().unwrap().pid, 10);
        let i = t.lookup(IPPROTO_TCP, sa("10.0.0.3:80"), sa("9.9.9.9:1")).unwrap();
        assert_eq!(i.owner.as_ref().unwrap().pid, 20);
    }

    fn owner(pid: u32) -> Owner {
        Owner::new(pid, &format!("p{pid}"))
    }

    #[test]
    fn container_sockets_seen_from_the_host() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        // curl in a container: 172.18.0.2:40000 -> 93.184.215.14:443.
        let sock = RawSock {
            proto: IPPROTO_TCP,
            local: sa("172.18.0.2:40000"),
            remote: sa("93.184.215.14:443"),
            state: "ESTABLISHED",
            inode: 7,
        };
        let listen = RawSock { local: sa("0.0.0.0:80"), remote: sa("0.0.0.0:0"), inode: 8, ..sock.clone() };
        let owners = HashMap::from([(7, owner(4242)), (8, owner(4243))]);
        let t = ContainerTable::build("web", vec![sock, listen], &owners);
        // veth/bridge: the container is the flow's remote end.
        let (o, exact) = t.lookup(IPPROTO_TCP, sa("93.184.215.14:443"), sa("172.18.0.2:40000")).unwrap();
        assert_eq!((o.pid, o.container.as_deref(), exact), (4242, Some("web"), true));
        // Uplink after masquerade: host address, same port.
        let (o, exact) = t.lookup(IPPROTO_TCP, sa("192.168.1.5:40000"), sa("93.184.215.14:443")).unwrap();
        assert_eq!((o.pid, exact), (4242, false));
        assert!(t.lookup(IPPROTO_TCP, sa("192.168.1.5:40001"), sa("93.184.215.14:443")).is_none(), "port changed");
        assert!(t.lookup(IPPROTO_UDP, sa("192.168.1.5:40000"), sa("93.184.215.14:443")).is_none());
    }

    #[test]
    fn owner_cache_scans_only_for_new_inodes() {
        let mut c = OwnerCache::default();
        let all = HashMap::from([(1, owner(10)), (2, owner(20))]);
        c.refresh(&HashSet::from([0, 1, 2]), |_| true, || all.clone());
        assert_eq!(c.scans, 1);
        c.refresh(&HashSet::from([0, 1, 2]), |_| true, || unreachable!("no new inode"));
        // Inode 3 has no owner: one scan, then it is a known miss.
        c.refresh(&HashSet::from([1, 2, 3]), |_| true, || all.clone());
        c.refresh(&HashSet::from([1, 2, 3]), |_| true, || unreachable!("3 is a known miss"));
        assert_eq!(c.scans, 2);
        // Closed sockets leave the cache.
        c.refresh(&HashSet::from([1]), |_| true, || unreachable!());
        assert_eq!(c.owners.len(), 1);
    }

    #[test]
    fn owner_cache_scans_only_for_wanted_inodes_and_not_too_often() {
        let all = HashMap::from([(1, owner(10)), (2, owner(20)), (3, owner(30))]);
        let mut c = OwnerCache { min_gap: std::time::Duration::from_secs(60), ..OwnerCache::default() };
        let inodes = HashSet::from([1, 2, 3]);
        c.refresh_wanted(&inodes, &HashSet::new(), |_| true, || unreachable!("nothing wanted"));
        c.refresh_wanted(&inodes, &HashSet::from([2]), |_| true, || all.clone());
        assert_eq!(c.scans, 1);
        assert!(c.owners.contains_key(&3), "one scan fills every inode");
        let more = HashSet::from([1, 2, 3, 4]);
        c.refresh_wanted(&more, &HashSet::from([4]), |_| true, || unreachable!("within min_gap"));
        assert_eq!(c.scans, 1);
    }

    #[test]
    fn owner_cache_rescans_when_owner_exits() {
        let mut c = OwnerCache::default();
        c.refresh(&HashSet::from([1]), |_| true, || HashMap::from([(1, owner(10))]));
        // pid 10 exited; its child 11 holds the socket now.
        c.refresh(&HashSet::from([1]), |pid| pid != 10, || HashMap::from([(1, owner(11))]));
        assert_eq!(c.owners[&1].pid, 11);
        assert_eq!(c.scans, 2);
    }

    #[test]
    fn unit_from_cgroup_path() {
        assert_eq!(unit_of("/system.slice/sshd.service"), "sshd.service");
        assert_eq!(
            unit_of("/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-1.scope"),
            "app-firefox-1.scope"
        );
        assert_eq!(unit_of("/system.slice/docker-abc.scope/init"), "docker-abc.scope");
        assert_eq!(unit_of("/kubepods/pod1"), "pod1");
        assert_eq!(unit_of("/"), "");
    }

    #[test]
    fn proc_cache_reads_each_pid_once() {
        let mut cache = ProcCache { users: Some(HashMap::from([(1000, "j".to_string())])), ..Default::default() };
        let raw = || Some(RawDetails { exe: "/usr/bin/curl".into(), uid: 1000, cgroup: "/user.slice/s.scope".into() });
        let mut a = Owner::new(7, "renamed");
        cache.fill(&mut a, |_| raw());
        let d = a.details.clone().unwrap();
        assert_eq!((d.exe.as_str(), d.user.as_str(), d.unit.as_str()), ("/usr/bin/curl", "j", "s.scope"));
        let mut b = Owner::new(7, "other");
        cache.fill(&mut b, |_| unreachable!("cached"));
        assert_eq!(b.details, a.details);
        // Process gone: the pid is read again when it shows up next.
        cache.prune(|_| false);
        let mut c = Owner::new(7, "new");
        cache.fill(&mut c, |_| None);
        assert_eq!(c.details, None);
    }

    #[test]
    fn listeners_match_address_or_wildcard() {
        let l = Listeners::build([
            (IPPROTO_TCP, sa("[::]:8000"), Owner::new(1, "python3")),
            (IPPROTO_UDP, sa("127.0.0.53:53"), Owner::new(2, "resolved")),
            (IPPROTO_UDP, sa("0.0.0.0:53"), Owner::new(3, "dnsmasq")),
        ]);
        assert_eq!(l.lookup(IPPROTO_TCP, sa("127.0.0.1:8000")).unwrap().pid, 1, "[::] takes v4");
        assert_eq!(l.lookup(IPPROTO_UDP, sa("127.0.0.53:53")).unwrap().pid, 2, "exact beats wildcard");
        assert_eq!(l.lookup(IPPROTO_UDP, sa("10.0.0.2:53")).unwrap().pid, 3);
        assert!(l.lookup(IPPROTO_UDP, sa("[fe80::1]:53")).is_none(), "0.0.0.0 does not take v6");
        assert!(l.lookup(IPPROTO_TCP, sa("10.0.0.2:8001")).is_none());
    }

    #[test]
    fn lookup_kind_tells_exact_from_fallback() {
        let t = table();
        assert!(t.lookup_kind(IPPROTO_TCP, sa("10.0.0.2:40000"), sa("1.1.1.1:443")).unwrap().1);
        assert!(!t.lookup_kind(IPPROTO_TCP, sa("10.0.0.2:80"), sa("9.9.9.9:1")).unwrap().1);
    }

    #[test]
    fn seed_marks_inbound_by_bound_socket_and_keeps_owner() {
        let sock = |proto, local: &str, remote: &str, state| RawSock { proto, local: sa(local), remote: sa(remote), state, inode: 1 };
        let owner = |pid| Owner { pid, comm: "a-very-long-process-name".into(), uid: Some(7), ..Default::default() };
        let socks = vec![
            (sock(IPPROTO_TCP, "[::]:22", "[::]:0", "LISTEN"), owner(10)),
            (sock(IPPROTO_TCP, "[::ffff:10.0.0.2]:22", "[::ffff:9.9.9.9]:5000", "ESTAB"), owner(11)),
            (sock(IPPROTO_TCP, "10.0.0.2:40000", "1.1.1.1:443", "ESTAB"), owner(12)),
            (sock(IPPROTO_UDP, "0.0.0.0:53", "0.0.0.0:0", ""), owner(13)),
            (sock(IPPROTO_UDP, "10.0.0.2:41000", "8.8.8.8:53", ""), owner(14)),
        ];
        let (conns, listeners) = seed_entries(&socks);
        assert_eq!(listeners.len(), 2);
        assert_eq!((listeners[0].0.family, listeners[0].0.port, listeners[0].1.tgid), (6, 22, 10));
        assert_eq!(listeners[0].1.uid, 7);
        assert_eq!(&listeners[0].1.comm[..COMM_LEN - 1], &b"a-very-long-pro"[..]);
        assert_eq!(listeners[0].1.comm[COMM_LEN - 1], 0, "comm ends with NUL");
        let find = |port| *conns.iter().find(|c| c.0.local_port == port).unwrap();
        let ssh = find(22);
        assert_eq!((ssh.1, ssh.2, ssh.0.family, ssh.0.remote_port), (DIR_IN, 11, 4, 5000), "mapped address as IPv4");
        assert_eq!(&ssh.0.remote_addr[..4], &[9, 9, 9, 9]);
        assert_eq!((find(40000).1, find(40000).2), (DIR_OUT, 12));
        assert_eq!((find(41000).1, find(41000).2), (DIR_OUT, 14));
        assert_eq!(conns.len(), 3);
    }
}
