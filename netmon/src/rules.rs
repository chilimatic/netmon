//! Rules held by the monitor: an ordered list, first match wins. A clean
//! stop removes them from the kernel. netmond pins its links, so after a
//! crash the last rules stay until the next start; local mode pins nothing.

use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
};

use netmon_common::{
    ACTION_ALLOW, ACTION_ASK, ACTION_DENY, DIR_IN, DIR_OUT, IPPROTO_TCP, IPPROTO_UDP, MAX_EXE_PATH, MAX_RULES, RULE_DIR,
    RULE_EXE, RULE_NET, RULE_PORT, RULE_PROTO, RuleEntry, rule_matches,
};

use crate::procmap::normalize;

/// What the UI blocks with one key: a one-field deny rule.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
}

impl From<BlockTarget> for Match {
    fn from(t: BlockTarget) -> Match {
        match t {
            BlockTarget::Net(ip, len) => Match { net: Some((ip, len)), ..Match::default() },
            BlockTarget::Port(p, port) => Match { proto: Some(p), ports: Some((port, port)), ..Match::default() },
            BlockTarget::Exe(path) => Match { exe: Some(path), ..Match::default() },
        }
    }
}

impl fmt::Display for BlockTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Match::from(self.clone()).fmt(f)
    }
}

pub fn proto_name(p: u8) -> &'static str {
    match p {
        IPPROTO_TCP => "tcp",
        IPPROTO_UDP => "udp",
        _ => "ip",
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Action {
    #[default]
    Allow,
    Deny,
    /// Default action only: ask the user about outbound connections.
    Ask,
}

impl Action {
    pub fn kernel(self) -> u8 {
        match self {
            Action::Allow => ACTION_ALLOW,
            Action::Deny => ACTION_DENY,
            Action::Ask => ACTION_ASK,
        }
    }
}

/// The side that opened a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Dir {
    /// This host.
    Out,
    /// The remote host.
    In,
}

impl Dir {
    pub fn kernel(self) -> u8 {
        match self {
            Dir::Out => DIR_OUT,
            Dir::In => DIR_IN,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Ask => "ask",
        })
    }
}

/// The conditions of a rule. Unset fields match anything; an empty match
/// matches all traffic.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Match {
    /// Remote network: address and prefix length.
    pub net: Option<(IpAddr, u8)>,
    pub proto: Option<u8>,
    /// Remote port range, inclusive.
    pub ports: Option<(u16, u16)>,
    /// Absolute exe path of the local process.
    pub exe: Option<String>,
    /// Who opened the connection.
    pub dir: Option<Dir>,
}

impl Match {
    pub fn check(&self) -> Result<(), String> {
        if let Some(p) = &self.exe
            && (!p.starts_with('/') || p.len() >= MAX_EXE_PATH)
        {
            return Err(format!("exe {p:?}: needs an absolute path under {MAX_EXE_PATH} bytes"));
        }
        if let Some(p) = &self.exe
            && p.chars().any(char::is_control)
        {
            return Err(format!("exe {p:?}: control characters"));
        }
        if let Some((ip, len)) = self.net {
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if len > max {
                return Err(format!("prefix /{len} too long for {ip}"));
            }
            // The rules file refuses host bits: a rule saved with them
            // would make the next start fail.
            let masked = crate::rulefile::mask(ip, len);
            if masked != ip {
                return Err(format!("{ip}/{len}: host bits set, did you mean {masked}/{len}?"));
            }
        }
        if let Some((lo, hi)) = self.ports
            && (lo == 0 || lo > hi)
        {
            return Err(format!("bad port range {lo}-{hi}"));
        }
        if let Some(p) = self.proto
            && p != IPPROTO_TCP
            && p != IPPROTO_UDP
        {
            return Err(format!("protocol {p} not supported (tcp or udp)"));
        }
        Ok(())
    }
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut parts = Vec::new();
        match self.dir {
            Some(Dir::Out) => parts.push("out".to_string()),
            Some(Dir::In) => parts.push("in".to_string()),
            None => {}
        }
        if let Some(p) = &self.exe {
            parts.push(format!("exe {p}"));
        }
        match (self.proto, self.ports) {
            (Some(p), Some((lo, hi))) if lo == hi => parts.push(format!("{} port {lo}", proto_name(p))),
            (Some(p), Some((lo, hi))) => parts.push(format!("{} port {lo}-{hi}", proto_name(p))),
            (Some(p), None) => parts.push(proto_name(p).to_string()),
            (None, Some((lo, hi))) if lo == hi => parts.push(format!("port {lo}")),
            (None, Some((lo, hi))) => parts.push(format!("port {lo}-{hi}")),
            (None, None) => {}
        }
        match self.net {
            Some((ip, len)) if len == if ip.is_ipv4() { 32 } else { 128 } => parts.push(format!("host {ip}")),
            Some((ip, len)) => parts.push(format!("net {ip}/{len}")),
            None => {}
        }
        if parts.is_empty() {
            return f.write_str("all traffic");
        }
        f.write_str(&parts.join(" "))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    /// Stable id for the UI. Not the kernel slot: that is the position.
    pub id: u32,
    pub action: Action,
    pub m: Match,
    pub comment: String,
    /// Packets and socket calls matched, over the whole run.
    pub hits: u64,
    /// Hits before the kernel table was last rewritten.
    pub hits_base: u64,
    /// Ends when the monitor stops; never saved to the rules file.
    pub temporary: bool,
    /// The rule ends at this time (seconds since 1970, UTC).
    #[serde(default)]
    pub until: Option<u64>,
}

/// Seconds since 1970, UTC.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
#[test]
fn time_left_is_short() {
    assert_eq!(time_left(100, 100), "0s");
    assert_eq!(time_left(3699, 100), "60m");
    assert_eq!(time_left(3700, 100), "1h");
    assert_eq!(time_left(3701, 100), "2h");
    assert_eq!(time_left(86_400, 0), "24h");
    assert_eq!(time_left(200_000, 0), "3d");
    assert_eq!(time_left(5, 100), "0s", "past");
}

/// Time left until `until`, short: "59m", "23h", "2d".
pub fn time_left(until: u64, now: u64) -> String {
    let s = until.saturating_sub(now);
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s.div_ceil(60)),
        3600..172_800 => format!("{}h", s.div_ceil(3600)),
        _ => format!("{}d", s.div_ceil(86_400)),
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.action, self.m)
    }
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Rules {
    /// In match order.
    pub rules: Vec<Rule>,
    /// Exe path -> exe id in the kernel, for every exe named by a rule.
    /// Ids are never reused, so a stale process mark can never name
    /// another exe.
    exe_ids: BTreeMap<String, u32>,
    next_exe_id: u32,
    next_id: u32,
    /// Action for TCP and UDP traffic no rule matches.
    pub default: Action,
    /// Blocked hostnames, in the order they were added.
    #[serde(default)]
    pub hosts: Vec<HostBlock>,
    /// Host block lists (files with many names).
    #[serde(default)]
    pub blocklists: Vec<Blocklist>,
}

/// A host block list: a file of hostnames, each blocking itself and the
/// names below it.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Blocklist {
    pub id: u32,
    /// Absolute path of the file.
    pub path: String,
    pub comment: String,
    /// Names read from the file.
    pub count: usize,
    /// Lines that held no hostname.
    pub skipped: usize,
    /// Why the file could not be read, empty if it was read.
    pub error: String,
    /// Addresses learned for its names, as last synced.
    pub addrs: usize,
    /// Connections denied for it since the start.
    pub hits: u64,
    /// The names. Not sent to the UI: lists hold up to millions of names.
    #[serde(skip)]
    pub names: std::sync::Arc<std::collections::HashSet<String>>,
}

impl Blocklist {
    /// Takes the names read from the file, or the read error.
    pub fn set_names(&mut self, names: Result<(std::collections::HashSet<String>, usize), String>) {
        match names {
            Ok((n, skipped)) => {
                self.count = n.len();
                self.skipped = skipped;
                self.error.clear();
                self.names = std::sync::Arc::new(n);
            }
            Err(e) => {
                self.count = 0;
                self.skipped = 0;
                self.error = e;
                self.names = Default::default();
            }
        }
    }

    pub fn matches(&self, name: &str) -> bool {
        crate::blocklist::contains(&self.names, name)
    }
}

/// Host block lists at most.
pub const MAX_BLOCKLISTS: usize = 32;

/// Patterns a host block list holds at most.
pub const MAX_HOST_BLOCKS: usize = 256;

/// A blocked hostname: `ads.example.com` blocks that name, `*.example.com`
/// blocks example.com and every name below it. The addresses come from DNS
/// answers and TLS server names.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HostBlock {
    pub id: u32,
    pub pattern: String,
    pub comment: String,
    /// Addresses learned for it, as last synced. For display.
    pub addrs: Vec<IpAddr>,
    /// Connections denied for it since the start.
    pub hits: u64,
}

impl HostBlock {
    pub fn matches(&self, name: &str) -> bool {
        host_matches(&self.pattern, name)
    }
}

/// Does `name` fall under `pattern`? Case and a final dot do not count.
pub fn host_matches(pattern: &str, name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(base) => name == base || name.ends_with(&format!(".{base}")),
        None => name == pattern,
    }
}

/// Checks a host pattern and gives its normal form (lower case, no final
/// dot): letters, digits, `-` and `_` in dot-separated labels, optionally
/// `*.` in front.
pub fn host_pattern(p: &str) -> Result<String, String> {
    let p = p.trim().trim_end_matches('.').to_ascii_lowercase();
    let base = p.strip_prefix("*.").unwrap_or(&p);
    let ok_label = |l: &str| {
        !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if base.is_empty() || base.len() > 253 || !base.split('.').all(ok_label) {
        return Err(format!("host {p:?}: not a hostname or *.domain"));
    }
    Ok(p)
}

impl Rules {
    /// Adds a blocked hostname. Returns its id.
    pub fn add_host(&mut self, pattern: &str, comment: &str) -> Result<u32, String> {
        let pattern = host_pattern(pattern)?;
        if comment.chars().any(char::is_control) {
            return Err("comment: control characters".into());
        }
        if self.hosts.iter().any(|h| h.pattern == pattern) {
            return Err(format!("host {pattern} is already blocked"));
        }
        if self.hosts.len() >= MAX_HOST_BLOCKS {
            return Err(format!("host block limit {MAX_HOST_BLOCKS} reached"));
        }
        let id = self.next_id;
        self.next_id += 1;
        self.hosts.push(HostBlock { id, pattern, comment: comment.to_string(), ..HostBlock::default() });
        Ok(id)
    }

    /// Removes a blocked hostname. Its pattern, if it existed.
    pub fn remove_host(&mut self, id: u32) -> Option<String> {
        let i = self.hosts.iter().position(|h| h.id == id)?;
        Some(self.hosts.remove(i).pattern)
    }

    /// Is a hostname blocked by any pattern or list?
    pub fn host_blocked(&self, name: &str) -> bool {
        self.hosts.iter().any(|h| h.matches(name)) || self.blocklists.iter().any(|l| l.matches(name))
    }

    /// Are there host blocks of any kind?
    pub fn has_host_blocks(&self) -> bool {
        !self.hosts.is_empty() || self.blocklists.iter().any(|l| l.count > 0)
    }

    /// Adds a host block list with the names read from it (`Err`: why the
    /// file could not be read; the list stays, with no names). Returns its id.
    pub fn add_blocklist(
        &mut self,
        path: &str,
        comment: &str,
        names: Result<(std::collections::HashSet<String>, usize), String>,
    ) -> Result<u32, String> {
        if !path.starts_with('/') || path.chars().any(char::is_control) {
            return Err(format!("blocklist {path:?}: use an absolute path"));
        }
        if comment.chars().any(char::is_control) {
            return Err("comment: control characters".into());
        }
        if self.blocklists.iter().any(|l| l.path == path) {
            return Err(format!("blocklist {path} is already loaded"));
        }
        if self.blocklists.len() >= MAX_BLOCKLISTS {
            return Err(format!("blocklist limit {MAX_BLOCKLISTS} reached"));
        }
        let id = self.next_id;
        self.next_id += 1;
        let mut l = Blocklist { id, path: path.to_string(), comment: comment.to_string(), ..Blocklist::default() };
        l.set_names(names);
        self.blocklists.push(l);
        Ok(id)
    }

    /// Names in all lists together.
    pub fn blocklist_names(&self) -> usize {
        self.blocklists.iter().map(|l| l.count).sum()
    }

    pub fn remove_blocklist(&mut self, id: u32) -> Option<String> {
        let i = self.blocklists.iter().position(|l| l.id == id)?;
        Some(self.blocklists.remove(i).path)
    }

    /// Inserts a rule at position `at` (clamped). Returns its id.
    pub fn insert(&mut self, at: usize, action: Action, m: Match, comment: &str) -> Result<u32, String> {
        if action == Action::Ask {
            return Err("ask is only a default action, not a rule action".into());
        }
        m.check()?;
        // Other admins see the comment in their Rules tab.
        if comment.chars().any(char::is_control) {
            return Err("comment: control characters".into());
        }
        if self.rules.iter().any(|r| r.action == action && r.m == m) {
            return Err(format!("{action} {m} already exists"));
        }
        if self.rules.len() >= MAX_RULES as usize {
            return Err(format!("rule limit {MAX_RULES} reached"));
        }
        if let Some(p) = &m.exe
            && !self.exe_ids.contains_key(p)
        {
            self.next_exe_id += 1;
            self.exe_ids.insert(p.clone(), self.next_exe_id);
        }
        let id = self.next_id;
        self.next_id += 1;
        let rule = Rule { id, action, m, comment: comment.to_string(), hits: 0, hits_base: 0, temporary: false, until: None };
        self.rules.insert(at.min(self.rules.len()), rule);
        Ok(id)
    }

    /// A UI block: a deny rule on top, so it wins over every other rule.
    pub fn block(&mut self, target: BlockTarget) -> Result<u32, String> {
        self.insert(0, Action::Deny, target.into(), "")
    }

    /// The deny rule with exactly this one-field match.
    pub fn find_block(&self, target: &BlockTarget) -> Option<&Rule> {
        let m = Match::from(target.clone());
        self.rules.iter().find(|r| r.action == Action::Deny && r.m == m)
    }

    pub fn set_temporary(&mut self, id: u32) {
        if let Some(r) = self.rules.iter_mut().find(|r| r.id == id) {
            r.temporary = true;
        }
    }

    /// Sets or clears the end time of rule `id`. False: no such rule.
    pub fn set_until(&mut self, id: u32, until: Option<u64>) -> bool {
        match self.rules.iter_mut().find(|r| r.id == id) {
            Some(r) => {
                r.until = until;
                true
            }
            None => false,
        }
    }

    /// Ids of the rules whose end time is `now` or earlier.
    pub fn expired(&self, now: u64) -> Vec<u32> {
        self.rules.iter().filter(|r| r.until.is_some_and(|u| u <= now)).map(|r| r.id).collect()
    }

    pub fn remove(&mut self, id: u32) -> Option<Rule> {
        let i = self.rules.iter().position(|r| r.id == id)?;
        let rule = self.rules.remove(i);
        if let Some(p) = &rule.m.exe
            && !self.rules.iter().any(|r| r.m.exe.as_ref() == Some(p))
        {
            self.exe_ids.remove(p);
        }
        Some(rule)
    }

    /// Exe path -> exe id of every exe named by a rule.
    pub fn exe_ids(&self) -> &BTreeMap<String, u32> {
        &self.exe_ids
    }

    /// The kernel table, in match order.
    pub fn entries(&self) -> Vec<RuleEntry> {
        self.rules.iter().map(|r| self.entry(r)).collect()
    }

    fn entry(&self, r: &Rule) -> RuleEntry {
        let mut e = RuleEntry { action: r.action.kernel(), ..RuleEntry::default() };
        if let Some(d) = r.m.dir {
            e.fields |= RULE_DIR;
            e.dir = d.kernel();
        }
        if let Some((ip, len)) = r.m.net {
            e.fields |= RULE_NET;
            (e.family, e.addr) = addr_bytes(ip);
            e.prefix = len;
        }
        if let Some(p) = r.m.proto {
            e.fields |= RULE_PROTO;
            e.proto = p;
        }
        if let Some((lo, hi)) = r.m.ports {
            e.fields |= RULE_PORT;
            (e.port_lo, e.port_hi) = (lo, hi);
        }
        if let Some(p) = &r.m.exe {
            e.fields |= RULE_EXE;
            e.exe = self.exe_ids.get(p).copied().unwrap_or(0);
        }
        e
    }

    /// The first rule that matches traffic to `remote` by a process running
    /// `exe` ("" if unknown) on a connection opened in direction `dir`,
    /// with the kernel's match logic.
    pub fn first_match(&self, proto: u8, remote: SocketAddr, exe: &str, dir: Dir) -> Option<&Rule> {
        let remote = normalize(remote);
        let (family, addr) = addr_bytes(remote.ip());
        let exe = self.exe_ids.get(exe).copied().unwrap_or(0);
        self.rules
            .iter()
            .find(|r| rule_matches(&self.entry(r), family, &addr, proto, remote.port(), exe, dir.kernel()))
    }

    /// Is this traffic denied, by a rule or the default? Ignores the
    /// kernel's exemptions (loopback, guard, DHCP).
    pub fn denies(&self, proto: u8, remote: SocketAddr, exe: &str, dir: Dir) -> bool {
        match self.first_match(proto, remote, exe, dir) {
            Some(r) => r.action == Action::Deny,
            None => (proto == IPPROTO_TCP || proto == IPPROTO_UDP) && self.default != Action::Allow,
        }
    }

    /// Does a deny rule block this exe entirely (no host, port or
    /// protocol in the rule)?
    pub fn denies_exe(&self, exe: &str) -> bool {
        !exe.is_empty()
            && self.rules.iter().any(|r| {
                r.action == Action::Deny
                    && r.m.exe.as_deref() == Some(exe)
                    && r.m.net.is_none()
                    && r.m.ports.is_none()
                    && r.m.proto.is_none()
            })
    }
}

/// Address family (4 or 6) and the address bytes, IPv4 in the first 4.
pub fn addr_bytes(ip: IpAddr) -> (u8, [u8; 16]) {
    let mut b = [0u8; 16];
    match ip {
        IpAddr::V4(v4) => {
            b[..4].copy_from_slice(&v4.octets());
            (4, b)
        }
        IpAddr::V6(v6) => (6, v6.octets()),
    }
}

/// The exe ids, also under the real path of each exe (`real` resolves
/// symlinks), for comparing with /proc/<pid>/exe.
pub fn with_real_paths(
    exes: &BTreeMap<String, u32>,
    real: impl Fn(&str) -> Option<std::path::PathBuf>,
) -> BTreeMap<String, u32> {
    let mut out = exes.clone();
    for (path, id) in exes {
        if let Some(r) = real(path).and_then(|r| r.to_str().map(str::to_string)) {
            out.entry(r).or_insert(*id);
        }
    }
    out
}

/// Groups running processes by the exes rules name: exe id -> pids.
pub fn pids_by_exe(running: impl Iterator<Item = (u32, String)>, exes: &BTreeMap<String, u32>) -> Vec<(u32, Vec<u32>)> {
    let mut out: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (pid, exe) in running {
        if let Some(id) = exes.get(&exe) {
            out.entry(*id).or_default().push(pid);
        }
    }
    out.into_iter().collect()
}

/// A guarded remote endpoint: address, protocol, direction (DIR_*, 0 both).
pub type GuardEndpoint = (SocketAddr, u8, u8);

/// Endpoints that are never blocked: the SSH client of the session netmon
/// runs in (TCP, both directions), and the DNS servers in resolv.conf
/// (port 53, UDP and TCP, outbound only). Loopback is guarded in the
/// kernel by address.
pub fn guard_endpoints(ssh_connection: Option<&str>, resolv_conf: &str) -> Vec<GuardEndpoint> {
    let mut out = Vec::new();
    // "client_ip client_port server_ip server_port": the client is the
    // remote end of the session on this host.
    if let Some(s) = ssh_connection {
        let mut f = s.split_whitespace();
        if let (Some(ip), Some(port)) = (f.next(), f.next())
            && let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), port.parse::<u16>())
        {
            out.push((normalize(SocketAddr::new(ip, port)), IPPROTO_TCP, 0));
        }
    }
    for line in resolv_conf.lines() {
        let mut f = line.split_whitespace();
        if f.next() == Some("nameserver")
            && let Some(ip) = f.next()
            // Drop a zone id such as fe80::1%eth0.
            && let Ok(ip) = ip.split('%').next().unwrap_or("").parse::<IpAddr>()
        {
            let ep = normalize(SocketAddr::new(ip, 53));
            out.push((ep, IPPROTO_UDP, DIR_OUT));
            out.push((ep, IPPROTO_TCP, DIR_OUT));
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
    fn blocks_match() {
        let mut r = Rules::default();
        r.block(BlockTarget::host("1.1.1.1".parse().unwrap())).unwrap();
        assert!(r.denies(IPPROTO_TCP, sa("1.1.1.1:443"), "", Dir::Out));
        assert!(r.denies(IPPROTO_UDP, sa("[::ffff:1.1.1.1]:53"), "", Dir::Out), "mapped v4");
        assert!(!r.denies(IPPROTO_TCP, sa("1.1.1.2:443"), "", Dir::Out));
        r.block(BlockTarget::Net("10.0.0.0".parse().unwrap(), 8)).unwrap();
        assert!(r.denies(IPPROTO_TCP, sa("10.200.3.4:1"), "", Dir::Out));
        assert!(!r.denies(IPPROTO_TCP, sa("11.0.0.1:1"), "", Dir::Out));
        r.block(BlockTarget::Net("2001:db8::".parse().unwrap(), 32)).unwrap();
        assert!(r.denies(IPPROTO_TCP, sa("[2001:db8:1::5]:80"), "", Dir::Out));
        r.block(BlockTarget::Port(IPPROTO_TCP, 25)).unwrap();
        assert!(r.denies(IPPROTO_TCP, sa("9.9.9.9:25"), "", Dir::Out));
        assert!(!r.denies(IPPROTO_UDP, sa("9.9.9.9:25"), "", Dir::Out));
    }

    #[test]
    fn client_input_is_checked_like_the_file() {
        let mut r = Rules::default();
        let net = |ip: &str, len| Match { net: Some((ip.parse().unwrap(), len)), ..Match::default() };
        assert!(r.insert(0, Action::Deny, net("10.1.0.0", 8), "").unwrap_err().contains("host bits"));
        r.insert(0, Action::Deny, net("10.0.0.0", 8), "").unwrap();
        let exe = Match { exe: Some("/usr/bin/x\u{1b}[2J".into()), ..Match::default() };
        assert!(r.insert(0, Action::Deny, exe, "").unwrap_err().contains("control"));
        assert!(r.insert(0, Action::Deny, net("10.0.0.0", 16), "a\nb").unwrap_err().contains("control"));
    }

    #[test]
    fn first_match_wins() {
        let mut r = Rules::default();
        let curl = || Match { exe: Some("/usr/bin/curl".into()), ..Match::default() };
        r.insert(9, Action::Deny, curl(), "").unwrap();
        // Inserted above the deny: curl may reach port 443 only.
        r.insert(0, Action::Allow, Match { ports: Some((443, 443)), proto: Some(IPPROTO_TCP), ..curl() }, "web")
            .unwrap();
        assert!(!r.denies(IPPROTO_TCP, sa("1.1.1.1:443"), "/usr/bin/curl", Dir::Out));
        assert_eq!(r.first_match(IPPROTO_TCP, sa("1.1.1.1:443"), "/usr/bin/curl", Dir::Out).unwrap().comment, "web");
        assert!(r.denies(IPPROTO_TCP, sa("1.1.1.1:80"), "/usr/bin/curl", Dir::Out));
        assert!(!r.denies(IPPROTO_TCP, sa("1.1.1.1:80"), "/usr/bin/wget", Dir::Out));
        assert!(!r.denies(IPPROTO_TCP, sa("1.1.1.1:80"), "", Dir::Out), "unknown exe never matches");
    }

    #[test]
    fn direction_and_default() {
        let mut r = Rules { default: Action::Deny, ..Rules::default() };
        r.insert(9, Action::Allow, Match { dir: Some(Dir::Out), ..Match::default() }, "").unwrap();
        assert!(!r.denies(IPPROTO_TCP, sa("1.1.1.1:443"), "", Dir::Out));
        assert!(r.denies(IPPROTO_TCP, sa("1.1.1.1:443"), "", Dir::In), "default deny for inbound");
        assert!(!r.denies(1, sa("1.1.1.1:0"), "", Dir::In), "default applies to tcp and udp only");
        let e = r.entries();
        assert_eq!((e[0].fields, e[0].dir, e[0].action), (RULE_DIR, DIR_OUT, ACTION_ALLOW));
    }

    #[test]
    fn display() {
        assert_eq!(BlockTarget::host("1.1.1.1".parse().unwrap()).to_string(), "host 1.1.1.1");
        assert_eq!(BlockTarget::Net("10.0.0.0".parse().unwrap(), 8).to_string(), "net 10.0.0.0/8");
        assert_eq!(BlockTarget::Port(IPPROTO_UDP, 53).to_string(), "udp port 53");
        assert_eq!(BlockTarget::Exe("/usr/bin/curl".into()).to_string(), "exe /usr/bin/curl");
        let m = Match {
            exe: Some("/usr/bin/curl".into()),
            proto: Some(IPPROTO_TCP),
            ports: Some((8000, 8100)),
            net: Some(("10.0.0.0".parse().unwrap(), 8)),
            dir: Some(Dir::In),
        };
        assert_eq!(m.to_string(), "in exe /usr/bin/curl tcp port 8000-8100 net 10.0.0.0/8");
        assert_eq!(Match::default().to_string(), "all traffic");
    }

    #[test]
    fn duplicates_limits_and_bad_fields_refused() {
        let mut r = Rules::default();
        r.block(BlockTarget::Port(IPPROTO_TCP, 1)).unwrap();
        assert!(r.block(BlockTarget::Port(IPPROTO_TCP, 1)).is_err());
        assert!(r.insert(0, Action::Allow, BlockTarget::Port(IPPROTO_TCP, 1).into(), "").is_ok(), "other action");
        assert!(r.block(BlockTarget::Exe("curl".into())).is_err(), "relative path");
        assert!(r.block(BlockTarget::Exe(format!("/{}", "a".repeat(300)))).is_err(), "too long");
        assert!(r.block(BlockTarget::Net("1.0.0.0".parse().unwrap(), 33)).is_err());
        let zero = Match { ports: Some((0, 5)), ..Match::default() };
        assert!(r.insert(0, Action::Deny, zero, "").is_err());
        let mut full = Rules::default();
        for p in 1..=MAX_RULES {
            full.block(BlockTarget::Port(IPPROTO_UDP, p as u16)).unwrap();
        }
        assert!(full.block(BlockTarget::Port(IPPROTO_TCP, 1)).unwrap_err().contains("limit"));
    }

    #[test]
    fn exe_ids_shared_and_released() {
        let mut r = Rules::default();
        let a = r.block(BlockTarget::Exe("/usr/bin/curl".into())).unwrap();
        let m = Match { exe: Some("/usr/bin/curl".into()), ports: Some((443, 443)), ..Match::default() };
        let b = r.insert(0, Action::Allow, m, "").unwrap();
        let w = r.block(BlockTarget::Exe("/usr/bin/wget".into())).unwrap();
        assert_eq!(r.exe_ids().get("/usr/bin/curl"), Some(&1));
        assert_eq!(r.exe_ids().get("/usr/bin/wget"), Some(&2));
        r.remove(a).unwrap();
        assert_eq!(r.exe_ids().get("/usr/bin/curl"), Some(&1), "still named by the allow rule");
        r.remove(b).unwrap();
        assert!(!r.exe_ids().contains_key("/usr/bin/curl"));
        r.block(BlockTarget::Exe("/usr/bin/nc".into())).unwrap();
        assert_eq!(r.exe_ids().get("/usr/bin/nc"), Some(&3), "ids never reused");
        assert!(r.denies_exe("/usr/bin/wget") && !r.denies_exe("/usr/bin/curl"));
        r.remove(w).unwrap();
    }

    #[test]
    fn compiles_to_entries() {
        let mut r = Rules::default();
        r.block(BlockTarget::Exe("/usr/bin/curl".into())).unwrap();
        r.block(BlockTarget::Net("10.0.0.0".parse().unwrap(), 8)).unwrap();
        r.block(BlockTarget::Port(IPPROTO_UDP, 53)).unwrap();
        let e = r.entries();
        assert_eq!(e[0], RuleEntry { fields: RULE_PROTO | RULE_PORT, proto: IPPROTO_UDP, port_lo: 53, port_hi: 53, action: ACTION_DENY, ..Default::default() });
        assert_eq!((e[1].fields, e[1].family, e[1].prefix, e[1].addr[0]), (RULE_NET, 4, 8, 10));
        assert_eq!((e[2].fields, e[2].exe), (RULE_EXE, 1));
    }

    #[test]
    fn guard_from_ssh_and_resolv_conf() {
        let g = guard_endpoints(
            Some("192.168.1.20 51234 192.168.1.5 22"),
            "# comment\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\noptions edns0\nsearch lan\n",
        );
        let out = |a| [(sa(a), IPPROTO_UDP, DIR_OUT), (sa(a), IPPROTO_TCP, DIR_OUT)];
        let mut want = vec![(sa("192.168.1.20:51234"), IPPROTO_TCP, 0)];
        want.extend(out("127.0.0.53:53"));
        want.extend(out("[fe80::1]:53"));
        assert_eq!(g, want, "resolvers outbound only");
        assert!(guard_endpoints(Some("garbage"), "").is_empty());
    }

    #[test]
    fn host_patterns_match_names_and_subdomains() {
        assert!(host_matches("ads.example.com", "ADS.example.com."));
        assert!(!host_matches("ads.example.com", "x.ads.example.com"));
        assert!(host_matches("*.example.com", "example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "badexample.com"));
        assert_eq!(host_pattern(" *.Example.COM. ").unwrap(), "*.example.com");
        assert!(host_pattern("a b.com").is_err());
        assert!(host_pattern("*.").is_err());
        assert!(host_pattern("x.*.com").is_err());
        let mut r = Rules::default();
        let id = r.add_host("*.example.com", "ads").unwrap();
        assert!(r.add_host("*.EXAMPLE.com", "").is_err(), "duplicate");
        assert!(r.host_blocked("cdn.example.com"));
        assert_eq!(r.remove_host(id).as_deref(), Some("*.example.com"));
        assert!(!r.host_blocked("cdn.example.com"));
    }

    #[test]
    fn only_a_whole_exe_block_marks_the_process() {
        let mut r = Rules::default();
        let curl = || Match { exe: Some("/usr/bin/curl".into()), ..Match::default() };
        r.insert(0, Action::Deny, Match { ports: Some((25, 25)), proto: Some(IPPROTO_TCP), ..curl() }, "").unwrap();
        assert!(!r.denies_exe("/usr/bin/curl"), "port-only rule");
        r.insert(0, Action::Deny, Match { dir: Some(Dir::Out), ..curl() }, "").unwrap();
        assert!(r.denies_exe("/usr/bin/curl"));
    }

    #[test]
    fn rule_path_through_a_symlink_matches_the_real_exe() {
        let mut exes = BTreeMap::new();
        exes.insert("/usr/sbin/twingated".to_string(), 7);
        let real = |p: &str| p.strip_prefix("/usr/sbin/").map(|n| std::path::PathBuf::from(format!("/usr/bin/{n}")));
        let all = with_real_paths(&exes, real);
        let got = pids_by_exe([(42, "/usr/bin/twingated".to_string())].into_iter(), &all);
        assert_eq!(got, vec![(7, vec![42])]);
    }

    #[test]
    fn running_processes_grouped_by_exe() {
        let mut exes = BTreeMap::new();
        exes.insert("/usr/bin/curl".to_string(), 3);
        exes.insert("/usr/bin/wget".to_string(), 4);
        let running = [(10, "/usr/bin/curl"), (11, "/usr/bin/bash"), (12, "/usr/bin/curl")];
        let got = pids_by_exe(running.iter().map(|(p, e)| (*p, e.to_string())), &exes);
        assert_eq!(got, vec![(3, vec![10, 12])]);
    }
}
