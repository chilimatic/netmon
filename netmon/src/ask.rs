//! Pending questions in ask mode: outbound connections that no rule
//! decides. The kernel drops their packets until the answer is written into
//! its connection state (once) or a rule decides them (scope answers); TCP
//! retransmits then get through.
//!
//! One question per program: a browser opening 200 connections asks once.
//! The question lists the destinations; the answer can cover the whole
//! program, one port, one destination, or only the waiting connections.

use std::{
    collections::VecDeque,
    net::IpAddr,
    time::{Duration, Instant},
};

use netmon_common::ConnKey;

use crate::{
    collector::addr,
    rules::{BlockTarget, Dir, Match},
};

/// No answer in this time: deny the waiting connections once.
pub const ASK_TIMEOUT: Duration = Duration::from_secs(30);
/// Questions kept at most; further connections are denied at once.
const MAX_PROMPTS: usize = 64;
/// Destinations per question at most; further ones are denied at once.
const MAX_DESTS: usize = 64;
/// Connections per destination at most.
const MAX_CONNS: usize = 256;

/// What a scope answer covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Scope {
    /// The program, any destination.
    Program,
    /// The program, this protocol and port, any host.
    Port,
    /// The program, this address, protocol and port.
    Destination,
}

impl Scope {
    pub const ALL: [Scope; 3] = [Scope::Program, Scope::Port, Scope::Destination];

    pub fn label(self) -> &'static str {
        match self {
            Scope::Program => "program",
            Scope::Port => "port",
            Scope::Destination => "destination",
        }
    }

    /// The next scope in `step` direction, wrapping around.
    pub fn step(self, step: isize) -> Scope {
        let i = Scope::ALL.iter().position(|s| *s == self).unwrap_or(0) as isize;
        Scope::ALL[(i + step).rem_euclid(Scope::ALL.len() as isize) as usize]
    }
}

/// One remote end a program wants to reach.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Dest {
    pub remote: IpAddr,
    pub port: u16,
    pub proto: u8,
    /// DNS name of the remote address, if known.
    pub host: Option<String>,
    pub conns: Vec<ConnKey>,
}

/// One question: a program wants to connect.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Prompt {
    /// Names the question in answers. Never reused.
    pub id: u64,
    pub pid: u32,
    pub comm: String,
    /// Empty if the process is unknown (forwarded traffic has no local
    /// socket) or was gone before netmon could read it. Then rules cannot
    /// name the program: only the port and destination scopes work.
    pub exe: String,
    pub user: String,
    pub dests: Vec<Dest>,
    #[serde(with = "crate::proto::age")]
    pub since: Instant,
    /// Destination the "once" answers and the destination scope use.
    pub selected: usize,
    pub scope: Scope,
}

impl Prompt {
    fn same_program(&self, exe: &str, pid: u32) -> bool {
        // Without an exe the pid is all that identifies the process.
        if exe.is_empty() { self.exe.is_empty() && self.pid == pid } else { self.exe == exe }
    }

    pub fn conns(&self) -> usize {
        self.dests.iter().map(|d| d.conns.len()).sum()
    }

    pub fn selected_dest(&self) -> Option<&Dest> {
        self.dests.get(self.selected)
    }

    /// The rule match for the current scope. Without an exe the rule
    /// covers every process, and the program scope (which would be "all
    /// traffic") gives None. The question is about outbound connections,
    /// so the rule is too: an answer never opens inbound traffic (from
    /// source port 53, or to the program's listeners).
    pub fn rule_match(&self) -> Option<Match> {
        let exe = (!self.exe.is_empty()).then(|| self.exe.clone());
        let d = self.selected_dest()?;
        let dir = Some(Dir::Out);
        Some(match self.scope {
            Scope::Program if exe.is_none() => return None,
            Scope::Program => Match { exe, dir, ..Match::default() },
            Scope::Port => Match { exe, dir, proto: Some(d.proto), ports: Some((d.port, d.port)), ..Match::default() },
            Scope::Destination => Match {
                exe,
                dir,
                proto: Some(d.proto),
                ports: Some((d.port, d.port)),
                ..Match::from(BlockTarget::host(d.remote))
            },
        })
    }

    pub fn move_selection(&mut self, step: isize) {
        let n = self.dests.len() as isize;
        if n > 0 {
            self.selected = (self.selected as isize + step).clamp(0, n - 1) as usize;
        }
    }

    /// Removes the destinations `decided` says are now decided by a rule.
    /// Returns their connections.
    pub fn drop_decided(&mut self, decided: impl Fn(&Dest) -> bool) -> Vec<ConnKey> {
        let mut out = Vec::new();
        self.dests.retain(|d| {
            let gone = decided(d);
            if gone {
                out.extend_from_slice(&d.conns);
            }
            !gone
        });
        self.selected = self.selected.min(self.dests.len().saturating_sub(1));
        out
    }
}

pub fn remote(key: &ConnKey) -> IpAddr {
    addr(key.family, &key.remote_addr, 0).ip()
}

/// What a new connection did to the questions.
#[derive(Debug, PartialEq)]
pub enum Added {
    /// A new question.
    New,
    /// Joined an open question (or was already in it).
    Joined,
    /// Too many open questions or destinations: deny this connection now.
    Full,
}

#[derive(Default)]
pub struct Asks {
    /// Oldest first; the first is the one shown.
    pub pending: VecDeque<Prompt>,
    next_id: u64,
}

impl Asks {
    /// Adds a connection of process `pid` running `exe`. `info` describes
    /// the process; its dests are ignored. `host` names the remote end.
    pub fn add(&mut self, key: ConnKey, info: Prompt, host: Option<String>) -> Added {
        let (remote, port, proto) = (remote(&key), key.remote_port, key.proto);
        let new_dest = || Dest { remote, port, proto, host: host.clone(), conns: vec![key] };
        if let Some(q) = self.pending.iter_mut().find(|q| q.same_program(&info.exe, info.pid)) {
            let full = q.dests.len() >= MAX_DESTS;
            match q.dests.iter_mut().find(|d| d.remote == remote && d.port == port && d.proto == proto) {
                Some(d) => {
                    if !d.conns.contains(&key) {
                        // Not kept: no answer or timeout would reach it.
                        if d.conns.len() >= MAX_CONNS {
                            return Added::Full;
                        }
                        d.conns.push(key);
                    }
                }
                None if full => return Added::Full,
                None => q.dests.push(new_dest()),
            }
            return Added::Joined;
        }
        if self.pending.len() >= MAX_PROMPTS {
            return Added::Full;
        }
        // An unknown process cannot get a program rule: start at port.
        let scope = if info.exe.is_empty() { Scope::Port } else { Scope::Program };
        self.next_id += 1;
        self.pending.push_back(Prompt { id: self.next_id, dests: vec![new_dest()], selected: 0, scope, ..info });
        Added::New
    }

    /// Takes the questions older than ASK_TIMEOUT.
    pub fn expired(&mut self, now: Instant) -> Vec<Prompt> {
        let (old, keep): (Vec<_>, Vec<_>) =
            self.pending.drain(..).partition(|p| now.duration_since(p.since) >= ASK_TIMEOUT);
        self.pending = keep.into();
        old
    }
}

#[cfg(test)]
mod tests {
    use netmon_common::IPPROTO_TCP;

    use super::*;

    fn key(last: u8, local_port: u16, remote_port: u16) -> ConnKey {
        let mut k = ConnKey { family: 4, proto: IPPROTO_TCP, local_port, remote_port, ..Default::default() };
        k.remote_addr[..4].copy_from_slice(&[93, 184, 215, last]);
        k
    }

    pub fn info(exe: &str, pid: u32, since: Instant) -> Prompt {
        Prompt {
            id: 0,
            pid,
            comm: "firefox".into(),
            exe: exe.into(),
            user: "j".into(),
            dests: Vec::new(),
            since,
            selected: 0,
            scope: Scope::Program,
        }
    }

    #[test]
    fn one_question_per_program() {
        let t0 = Instant::now();
        let mut a = Asks::default();
        let ff = "/usr/lib/firefox/firefox";
        assert_eq!(a.add(key(14, 1, 443), info(ff, 10, t0), None), Added::New);
        assert_eq!(a.add(key(14, 2, 443), info(ff, 11, t0), None), Added::Joined, "other pid, same exe");
        assert_eq!(a.add(key(14, 2, 443), info(ff, 10, t0), None), Added::Joined, "duplicate");
        assert_eq!(a.add(key(15, 3, 443), info(ff, 10, t0), Some("cdn.example".into())), Added::Joined);
        assert_eq!(a.add(key(14, 4, 80), info(ff, 10, t0), None), Added::Joined);
        let p = &a.pending[0];
        assert_eq!((a.pending.len(), p.dests.len(), p.conns()), (1, 3, 4));
        assert_eq!(p.dests[1].host.as_deref(), Some("cdn.example"));
        // Unknown exe: only the same pid joins.
        assert_eq!(a.add(key(16, 1, 1), info("", 20, t0), None), Added::New);
        assert_eq!(a.add(key(16, 2, 1), info("", 21, t0), None), Added::New);
    }

    #[test]
    fn scopes_make_matches() {
        let t0 = Instant::now();
        let mut a = Asks::default();
        a.add(key(14, 1, 443), info("/usr/bin/curl", 1, t0), None);
        a.add(key(15, 2, 80), info("/usr/bin/curl", 1, t0), None);
        let p = &mut a.pending[0];
        p.move_selection(5);
        assert_eq!(p.selected, 1, "clamped");
        assert_eq!(p.rule_match().unwrap().to_string(), "out exe /usr/bin/curl");
        p.scope = p.scope.step(1);
        assert_eq!(p.rule_match().unwrap().to_string(), "out exe /usr/bin/curl tcp port 80");
        p.scope = p.scope.step(1);
        assert_eq!(p.rule_match().unwrap().to_string(), "out exe /usr/bin/curl tcp port 80 host 93.184.215.15");
        assert_eq!(p.scope.step(1), Scope::Program, "wraps");
        assert_eq!(Scope::Program.step(-1), Scope::Destination);
        let gone = p.drop_decided(|d| d.port == 80);
        assert_eq!((gone.len(), p.dests.len(), p.selected), (1, 1, 0));
        let mut unknown = info("", 1, t0);
        unknown.dests = p.dests.clone();
        assert_eq!(unknown.rule_match(), None, "no exe: no program rule");
        unknown.scope = Scope::Port;
        assert_eq!(unknown.rule_match().unwrap().to_string(), "out tcp port 443", "any process, outbound only");
        let mut a2 = Asks::default();
        a2.add(key(9, 1, 53), info("", 0, t0), None);
        assert_eq!(a2.pending[0].scope, Scope::Port, "unknown process starts at port scope");
    }

    #[test]
    fn timeout_and_limits() {
        let t0 = Instant::now();
        let mut a = Asks::default();
        for i in 0..MAX_PROMPTS {
            let exe = format!("/bin/p{i}");
            assert_eq!(a.add(key(1, 1, 1), info(&exe, 1, t0 + Duration::from_secs(i as u64)), None), Added::New);
        }
        assert_eq!(a.add(key(1, 1, 1), info("/bin/new", 1, t0), None), Added::Full);
        for port in 2..=MAX_DESTS as u16 {
            assert_eq!(a.add(key(1, 1, port), info("/bin/p0", 1, t0), None), Added::Joined);
        }
        assert_eq!(a.add(key(1, 1, 9999), info("/bin/p0", 1, t0), None), Added::Full, "too many destinations");
        let old = a.expired(t0 + ASK_TIMEOUT + Duration::from_secs(2));
        assert_eq!(old.len(), 3, "asked at 0, 1 and 2 s");
        assert_eq!(a.pending.len(), MAX_PROMPTS - 3);
    }
}
