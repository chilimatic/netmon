//! Maps sockets to the owning process with /proc.
//! Reads /proc/net/{tcp,tcp6,udp,udp6} for socket inodes, then
//! /proc/<pid>/fd for which process holds each inode.
//! Only sockets in this process's network namespace are visible.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::Path,
};

use netmon_common::{IPPROTO_TCP, IPPROTO_UDP};
use procfs::{
    net::TcpState,
    process::{FDTarget, all_processes},
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    /// Task name. Any process can change its own; never proof of identity.
    pub comm: String,
    pub uid: Option<u32>,
    /// Set by `ProcCache::fill`. None until then, or when unreadable
    /// (process gone, kernel thread).
    pub details: Option<ProcDetails>,
}

/// Facts about a process that the process itself cannot fake.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
        let addr = if self.ip == ip {
            0
        } else if self.ip.is_unspecified() && (self.ip.is_ipv6() || ip.is_ipv4()) {
            // [::] also takes IPv4 on dual-stack sockets; 0.0.0.0 only IPv4.
            2
        } else {
            return None;
        };
        Some(addr + u8::from(!self.unconnected))
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

    pub fn lookup(&self, proto: u8, local: SocketAddr, remote: SocketAddr) -> Option<&SockInfo> {
        let (local, remote) = (normalize(local), normalize(remote));
        if let Some(i) = self.exact.get(&(proto, local, remote)) {
            return Some(i);
        }
        self.by_port
            .get(&(proto, local.port()))?
            .iter()
            .filter_map(|b| b.rank(local.ip()).map(|r| (r, &b.info)))
            .min_by_key(|(r, _)| *r)
            .map(|(_, i)| i)
    }

    /// Reads the current socket table from /proc. Owners come from the
    /// cache, which scans /proc/*/fd only for sockets it has not seen.
    pub fn read(cache: &mut OwnerCache) -> Self {
        let socks = read_sockets();
        let inodes: HashSet<u64> = socks.iter().map(|s| s.inode).collect();
        cache.refresh(&inodes, |pid| Path::new(&format!("/proc/{pid}")).exists(), read_owners);
        Self::build(socks, &cache.owners)
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
        // A process that exits can leave its socket to a child (fork, then
        // exit). Drop the dead owner so the next scan finds the new one.
        let mut live: HashMap<u32, bool> = HashMap::new();
        self.owners
            .retain(|i, o| inodes.contains(i) && *live.entry(o.pid).or_insert_with(|| alive(o.pid)));
        self.misses.retain(|i| inodes.contains(i));
        let new = inodes.iter().any(|i| *i != 0 && !self.owners.contains_key(i) && !self.misses.contains(i));
        if !new {
            return;
        }
        let found = scan();
        self.scans += 1;
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
}

