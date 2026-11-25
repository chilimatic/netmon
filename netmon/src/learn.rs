//! Learning mode: allow rules suggested from the connection log. Run with
//! the default "allow" for some days, then add the suggestions and switch
//! the default to "deny" or "ask": the programs keep what they used.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    net::IpAddr,
    path::Path,
};

use crate::{
    connlog::Entry,
    rules::{Action, Dir, Match, Rules},
};

/// More ports than this for one program and protocol: one rule without a
/// port.
pub const MAX_PORTS: usize = 3;
/// Destinations named in a suggestion's comment.
const EXAMPLES: usize = 3;

/// One suggested allow rule.
#[derive(Clone, Debug, PartialEq)]
pub struct Suggestion {
    pub m: Match,
    /// Destinations (address and port) seen for it.
    pub count: usize,
    /// Hostnames, else addresses, of some destinations.
    pub examples: Vec<String>,
    /// Picked to add (all start picked).
    pub picked: bool,
}

impl Suggestion {
    pub fn comment(&self) -> String {
        let s = if self.count == 1 { "" } else { "s" };
        format!("learned: {} destination{s}, e.g. {}", self.count, self.examples.join(", "))
    }
}

/// Reads the connection log and its rotated part (`.1`), oldest first.
pub fn read_log(path: &Path) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    let old = path.with_extension("log.1");
    for p in [old.as_path(), path] {
        match std::fs::read_to_string(p) {
            Ok(text) => out.extend(text.lines().filter_map(|l| serde_json::from_str::<Entry>(l).ok())),
            Err(e) if p == path => return Err(format!("{}: {e}", p.display())),
            Err(_) => {}
        }
    }
    Ok(out)
}

/// Nameservers from resolv.conf text: DNS to them is always allowed (the
/// lockout guard), so no rule is needed.
pub fn resolvers(resolv_conf: &str) -> HashSet<IpAddr> {
    resolv_conf
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|a| a.trim().parse().ok())
        .collect()
}

/// Allow rules that cover the `new` connections of the log, one per
/// program, direction and protocol (and port, for at most MAX_PORTS
/// ports). Connections that `rules` already allows are left out, also
/// with the default action. Connections without an exe cannot have a rule.
pub fn suggest(log: &[Entry], rules: &Rules, resolvers: &HashSet<IpAddr>) -> Vec<Suggestion> {
    // (exe, dir, proto) -> port -> destinations (address, host).
    type Dests = BTreeMap<u16, BTreeSet<(IpAddr, String)>>;
    let mut groups: BTreeMap<(String, Dir, u8), Dests> = BTreeMap::new();
    let mut strict = rules.clone();
    strict.default = Action::Deny;
    // Addresses each program connected out to: an "in" line from one of
    // them is a reply (STUN, WireGuard, a server on a high port).
    let outbound: HashSet<(&str, IpAddr)> =
        log.iter().filter(|e| e.event == "new" && e.dir == "out").map(|e| (e.exe.as_str(), e.remote)).collect();
    for e in log.iter().filter(|e| e.event == "new" && !e.exe.is_empty()) {
        let dir = match e.dir.as_str() {
            "out" => Dir::Out,
            "in" => Dir::In,
            _ => continue,
        };
        let proto = match e.proto.as_str() {
            "tcp" => netmon_common::IPPROTO_TCP,
            "udp" => netmon_common::IPPROTO_UDP,
            _ => continue,
        };
        if e.remote.is_loopback() || (dir == Dir::Out && e.port == 53 && resolvers.contains(&e.remote)) {
            continue;
        }
        // A real inbound connection comes from a client port. An "in" line
        // from a service port (a DNS answer, HTTPS from port 443) is the
        // reply of an outbound connection whose first packet the monitor
        // saw inbound, for example one opened before it started.
        if dir == Dir::In && (e.port < 1024 || outbound.contains(&(e.exe.as_str(), e.remote))) {
            continue;
        }
        // Already allowed by a rule (not by the default): nothing to learn.
        let remote = std::net::SocketAddr::new(e.remote, e.port);
        if strict.first_match(proto, remote, &e.exe, dir).is_some_and(|r| r.action == Action::Allow) {
            continue;
        }
        // Inbound rules cannot name the local port: the remote port is the
        // client's, so it is not kept.
        let port = if dir == Dir::Out { e.port } else { 0 };
        groups.entry((e.exe.clone(), dir, proto)).or_default().entry(port).or_default().insert((e.remote, e.host.clone()));
    }
    let mut out = Vec::new();
    for ((exe, dir, proto), ports) in groups {
        let base = Match { exe: Some(exe), dir: Some(dir), proto: Some(proto), ..Match::default() };
        let make = |m: Match, dests: Vec<&(IpAddr, String)>| {
            let mut examples: Vec<String> = Vec::new();
            for (ip, host) in &dests {
                let label = if host.is_empty() { ip.to_string() } else { host.clone() };
                if !examples.contains(&label) && examples.len() < EXAMPLES {
                    examples.push(label);
                }
            }
            Suggestion { m, count: dests.len(), examples, picked: true }
        };
        if dir == Dir::Out && ports.len() <= MAX_PORTS {
            for (port, dests) in &ports {
                let m = Match { ports: Some((*port, *port)), ..base.clone() };
                out.push(make(m, dests.iter().collect()));
            }
        } else {
            out.push(make(base, ports.values().flatten().collect()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(exe: &str, dir: &str, proto: &str, remote: &str, port: u16, host: &str) -> Entry {
        Entry {
            time: "2026-11-25T10:00:00Z".into(),
            event: "new".into(),
            dir: dir.into(),
            proto: proto.into(),
            remote: remote.parse().unwrap(),
            port,
            host: host.into(),
            pid: 1,
            comm: "x".into(),
            exe: exe.into(),
        }
    }

    #[test]
    fn groups_by_program_and_port_and_skips_what_is_allowed() {
        let log = vec![
            e("/usr/bin/curl", "out", "tcp", "93.184.215.14", 443, "example.com"),
            e("/usr/bin/curl", "out", "tcp", "1.1.1.1", 443, ""),
            e("/usr/bin/curl", "out", "tcp", "1.1.1.1", 80, ""),
            e("/usr/bin/curl", "out", "udp", "100.95.0.251", 53, ""),
            // Many ports: one rule without a port.
            e("/usr/bin/torrent", "out", "udp", "5.5.5.1", 6881, ""),
            e("/usr/bin/torrent", "out", "udp", "5.5.5.2", 6882, ""),
            e("/usr/bin/torrent", "out", "udp", "5.5.5.3", 6883, ""),
            e("/usr/bin/torrent", "out", "udp", "5.5.5.4", 6884, ""),
            e("/usr/sbin/sshd", "in", "tcp", "10.0.0.9", 51234, ""),
            e("/usr/bin/app", "in", "udp", "100.95.0.251", 53, ""),
            e("/usr/bin/app", "in", "tcp", "1.2.3.4", 443, "api.example.com"),
            // A STUN reply: the program connected out to that address first.
            e("/usr/bin/call", "out", "udp", "74.125.1.1", 19302, ""),
            e("/usr/bin/call", "in", "udp", "74.125.1.1", 19302, ""),
            e("", "out", "tcp", "8.8.8.8", 443, ""),
            e("/usr/bin/ok", "out", "tcp", "8.8.8.8", 443, ""),
            Entry { event: "denied".into(), ..e("/usr/bin/x", "out", "tcp", "8.8.8.8", 443, "") },
        ];
        let mut rules = Rules::default();
        rules.insert(0, Action::Allow, Match { exe: Some("/usr/bin/ok".into()), ..Match::default() }, "").unwrap();
        let resolvers = resolvers("# x\nnameserver 100.95.0.251\nnameserver fe80::1%eth0\n");
        let got: Vec<(String, String)> =
            suggest(&log, &rules, &resolvers).iter().map(|s| (format!("{}", s.m), s.comment())).collect();
        assert_eq!(
            got,
            vec![
                ("out exe /usr/bin/call udp port 19302".into(), "learned: 1 destination, e.g. 74.125.1.1".into()),
                ("out exe /usr/bin/curl tcp port 80".into(), "learned: 1 destination, e.g. 1.1.1.1".into()),
                ("out exe /usr/bin/curl tcp port 443".into(), "learned: 2 destinations, e.g. 1.1.1.1, example.com".into()),
                ("out exe /usr/bin/torrent udp".into(), "learned: 4 destinations, e.g. 5.5.5.1, 5.5.5.2, 5.5.5.3".into()),
                ("in exe /usr/sbin/sshd tcp".into(), "learned: 1 destination, e.g. 10.0.0.9".into()),
            ]
        );
    }

    #[test]
    fn reads_the_log_and_its_rotated_part() {
        let _lock = crate::test_fs_lock();
        let dir = std::env::temp_dir().join(format!("netmon-learn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let line = |port: u16| serde_json::to_string(&e("/usr/bin/curl", "out", "tcp", "1.1.1.1", port, "")).unwrap();
        std::fs::write(dir.join("connections.log.1"), format!("{}\n", line(1))).unwrap();
        std::fs::write(dir.join("connections.log"), format!("{}\nbroken\n{}\n", line(2), line(3))).unwrap();
        let got: Vec<u16> = read_log(&dir.join("connections.log")).unwrap().iter().map(|e| e.port).collect();
        assert_eq!(got, vec![1, 2, 3]);
        assert!(read_log(&dir.join("missing.log")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
