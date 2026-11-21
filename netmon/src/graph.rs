//! The connection graph: this host in the middle, processes on a ring
//! around it, remote ends on an outer ring. Only the model and the layout
//! are here. ui.rs draws them.

use std::{
    collections::{BTreeMap, HashMap},
    f64::consts::TAU,
    net::IpAddr,
};

use netmon_common::{ACTION_ALLOW, ACTION_ASK, ACTION_DENY};

use crate::{app::owner_cols, collector::Collector, ifaces::Names};

/// Processes shown at most. The others count in `Graph::hidden`.
pub const MAX_PROCS: usize = 12;
/// Remote ends shown per process. The others share one "+n more" node.
pub const MAX_REMOTES: usize = 4;
/// Radius of the process ring and of the remote ring (canvas units).
pub const PROC_RING: f64 = 0.45;
pub const REMOTE_RING: f64 = 0.95;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Host,
    Process,
    Remote,
    /// Several remote ends of one process.
    More,
}

/// What the kernel decided for the connections of an edge. The worst
/// one wins: one denied connection makes the edge red.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// No rule is in force, or the kernel keeps no state for it.
    #[default]
    None,
    Allow,
    Ask,
    Deny,
}

impl Verdict {
    fn of(action: u8) -> Self {
        match action {
            ACTION_ALLOW => Verdict::Allow,
            ACTION_ASK => Verdict::Ask,
            ACTION_DENY => Verdict::Deny,
            _ => Verdict::None,
        }
    }
}

/// Traffic of one process to one remote end.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Agg {
    /// Bytes per second.
    pub tx: f64,
    pub rx: f64,
    pub conns: usize,
    pub verdict: Verdict,
}

impl Agg {
    fn add(&mut self, o: &Agg) {
        self.tx += o.tx;
        self.rx += o.rx;
        self.conns += o.conns;
        self.verdict = self.verdict.max(o.verdict);
    }

    fn rate(&self) -> f64 {
        self.tx + self.rx
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub kind: Kind,
    pub label: String,
    pub x: f64,
    pub y: f64,
    pub traffic: Agg,
    /// What `b` blocks for this node.
    pub target: Target,
}

/// What a node stands for, for blocking it.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Target {
    /// Nothing to block: this host, "+n more", a container, several exes.
    #[default]
    None,
    /// Every process of this exe.
    Exe(String),
    /// A hostname pattern (Hosts tab).
    Host(String),
    /// One remote address.
    Addr(IpAddr),
}

/// What the inner and the outer ring show. `z` switches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Level {
    /// Processes and remote hosts.
    #[default]
    Process,
    /// Containers (and the host's own processes as one node) and remote
    /// hosts.
    Container,
    /// Processes and remote domains (`*.example.com`).
    Domain,
}

impl Level {
    pub fn next(self) -> Self {
        match self {
            Level::Process => Level::Container,
            Level::Container => Level::Domain,
            Level::Domain => Level::Process,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Level::Process => "process",
            Level::Container => "container",
            Level::Domain => "domain",
        }
    }
}

/// The registrable part of a hostname, roughly: the last two labels, or
/// three under a short second level such as `co.uk`.
pub fn domain(name: &str) -> String {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    let n = labels.len();
    let short = |l: &str| matches!(l, "co" | "com" | "org" | "net" | "gov" | "ac" | "edu");
    let keep = if n >= 3 && labels[n - 1].len() == 2 && short(labels[n - 2]) { 3 } else { 2 };
    labels[n.saturating_sub(keep)..].join(".")
}

/// Block targets of the labels of both rings.
#[derive(Default)]
pub struct Targets {
    pub inner: HashMap<String, Target>,
    pub outer: HashMap<String, Target>,
}

/// From a process node to a remote node. `tx` flows outward.
#[derive(Clone, Debug, PartialEq)]
pub struct Edge {
    pub from: usize,
    pub to: usize,
    pub traffic: Agg,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// Processes left out (over MAX_PROCS).
    pub hidden: usize,
}

/// Process label -> remote label -> traffic.
pub type Groups = BTreeMap<String, BTreeMap<String, Agg>>;

/// Groups the flows by process and remote end (hostname if known and
/// `show_hosts`, else the address). Flows of bridges and veths repeat
/// the uplink's: they count only with `show_virtual`.
pub fn groups(c: &Collector, names: &Names, show_virtual: bool, show_hosts: bool, level: Level) -> (Groups, Targets) {
    let mut out = Groups::new();
    let mut t = Targets::default();
    for f in c.flows.values().filter(|f| show_virtual || !names.kind(f.key.ifindex).is_virtual()) {
        let process = match (level, &f.owner) {
            (Level::Container, Some(o)) => match &o.container {
                Some(c) => format!("container:{c}"),
                None => "host processes".into(),
            },
            (Level::Container, None) => "host processes".into(),
            _ => owner_cols(f).0,
        };
        let exe = f.owner.as_ref().and_then(|o| o.details.as_ref()).map(|d| d.exe.clone()).filter(|e| !e.is_empty());
        let inner = match (level, exe) {
            (Level::Container, _) | (_, None) => Target::None,
            (_, Some(e)) => Target::Exe(e),
        };
        // One label with two exes blocks nothing: it is not clear which.
        t.inner.entry(process.clone()).and_modify(|old| if *old != inner { *old = Target::None }).or_insert(inner);
        let ip = crate::procmap::normalize(f.remote).ip();
        let (remote, outer) = match f.host.clone().filter(|_| show_hosts) {
            Some(h) if level == Level::Domain => {
                let d = domain(&h);
                (format!("*.{d}"), Target::Host(format!("*.{d}")))
            }
            Some(h) => (h.clone(), Target::Host(h)),
            None => (ip.to_string(), Target::Addr(ip)),
        };
        t.outer.insert(remote.clone(), outer);
        let a = Agg {
            tx: f.tx_rate,
            rx: f.rx_rate,
            conns: 1,
            verdict: f.conn.map_or(Verdict::None, |s| Verdict::of(s.action)),
        };
        out.entry(process).or_default().entry(remote).or_default().add(&a);
    }
    (out, t)
}

/// The graph of the flows, with block targets.
pub fn build(c: &Collector, names: &Names, show_virtual: bool, show_hosts: bool, level: Level) -> Graph {
    let (groups, targets) = groups(c, names, show_virtual, show_hosts, level);
    let mut g = layout(&groups);
    for n in &mut g.nodes {
        n.target = match n.kind {
            Kind::Process => targets.inner.get(&n.label).cloned().unwrap_or_default(),
            Kind::Remote => targets.outer.get(&n.label).cloned().unwrap_or_default(),
            Kind::Host | Kind::More => Target::None,
        };
    }
    g
}

/// Places the nodes. The busiest MAX_PROCS processes are shown, in name
/// order around the ring, so a process keeps its place while the set
/// stays the same. Each process gets a sector of the outer ring for its
/// remote ends.
pub fn layout(groups: &Groups) -> Graph {
    let mut procs: Vec<(&String, &BTreeMap<String, Agg>)> = groups.iter().collect();
    let total = |r: &BTreeMap<String, Agg>| r.values().map(Agg::rate).sum::<f64>();
    procs.sort_by(|a, b| total(b.1).total_cmp(&total(a.1)).then(a.0.cmp(b.0)));
    let hidden = procs.len().saturating_sub(MAX_PROCS);
    procs.truncate(MAX_PROCS);
    procs.sort_by(|a, b| a.0.cmp(b.0));

    let mut g = Graph { hidden, ..Graph::default() };
    let mut host = Agg::default();
    for (_, remotes) in &procs {
        for a in remotes.values() {
            host.add(a);
        }
    }
    g.nodes.push(Node { kind: Kind::Host, label: "this host".into(), x: 0.0, y: 0.0, traffic: host, target: Target::None });
    let n = procs.len().max(1) as f64;
    for (i, (name, remotes)) in procs.iter().enumerate() {
        // Start at the top, clockwise.
        let angle = TAU / 4.0 - TAU * i as f64 / n;
        let mut traffic = Agg::default();
        for a in remotes.values() {
            traffic.add(a);
        }
        let p = g.nodes.len();
        g.nodes.push(Node {
            kind: Kind::Process,
            label: (*name).clone(),
            x: PROC_RING * angle.cos(),
            y: PROC_RING * angle.sin(),
            traffic,
            target: Target::None,
        });
        // The busiest remote ends, then the rest in one node.
        let mut list: Vec<(&String, &Agg)> = remotes.iter().collect();
        list.sort_by(|a, b| b.1.rate().total_cmp(&a.1.rate()).then(a.0.cmp(b.0)));
        let mut shown: Vec<(Kind, String, Agg)> = Vec::new();
        let mut rest = Agg::default();
        for (k, (label, a)) in list.iter().enumerate() {
            if k < MAX_REMOTES || list.len() == MAX_REMOTES + 1 {
                shown.push((Kind::Remote, (*label).clone(), **a));
            } else {
                rest.add(a);
            }
        }
        shown.sort_by(|a, b| a.1.cmp(&b.1));
        if rest.conns > 0 {
            let more = list.len() - MAX_REMOTES;
            shown.push((Kind::More, format!("+{more} more"), rest));
        }
        let sector = TAU / n * 0.8;
        let k = shown.len() as f64;
        for (j, (kind, label, traffic)) in shown.into_iter().enumerate() {
            let a = if k <= 1.0 { angle } else { angle + sector * ((j as f64 + 0.5) / k - 0.5) };
            let r = g.nodes.len();
            g.nodes.push(Node { kind, label, x: REMOTE_RING * a.cos(), y: REMOTE_RING * a.sin(), traffic, target: Target::None });
            g.edges.push(Edge { from: p, to: r, traffic });
        }
    }
    g
}

/// Edge lengths per second that dots of this rate move. More bytes per
/// second move faster, on a log scale.
pub fn speed(rate: f64) -> f64 {
    if rate < 1.0 { 0.0 } else { 0.15 + 0.08 * rate.log10() }
}

/// How many dots show this rate: 1 to 4, none below 1 B/s.
pub fn dot_count(rate: f64) -> usize {
    if rate < 1.0 { 0 } else { (rate.log10() / 2.0).ceil().clamp(1.0, 4.0) as usize }
}

/// Where `n` evenly spaced dots are at `phase`, as fractions 0..1 along
/// the edge. The caller advances the phase by speed times time, so a new
/// rate changes the speed but never makes the dots jump.
pub fn dots_at(phase: f64, n: usize) -> Vec<f64> {
    (0..n).map(|i| (phase + i as f64 / n.max(1) as f64).rem_euclid(1.0)).collect()
}

/// Motion of one edge between frames: the shown rates follow the real
/// ones over about half a second, and the phases add up.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Motion {
    pub up: f64,
    pub down: f64,
    pub phase_up: f64,
    pub phase_down: f64,
}

impl Motion {
    /// Advances by `dt` seconds toward the rates `tx` and `rx`.
    pub fn step(&mut self, dt: f64, tx: f64, rx: f64) {
        let k = (dt / 0.5).clamp(0.0, 1.0);
        self.up += (tx - self.up) * k;
        self.down += (rx - self.down) * k;
        self.phase_up = (self.phase_up + dt * speed(self.up)).rem_euclid(1.0);
        self.phase_down = (self.phase_down + dt * speed(self.down)).rem_euclid(1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg(rate: f64) -> Agg {
        Agg { tx: rate, rx: 0.0, conns: 1, verdict: Verdict::Allow }
    }

    fn sample(procs: usize, remotes: usize) -> Groups {
        let mut g = Groups::new();
        for p in 0..procs {
            let r = g.entry(format!("p{p:02}")).or_default();
            for i in 0..remotes {
                r.insert(format!("10.0.0.{i}"), agg((i + 1) as f64 * 100.0));
            }
        }
        g
    }

    #[test]
    fn positions_stay_put_between_ticks() {
        let a = layout(&sample(3, 2));
        let mut later = sample(3, 2);
        // Rates change, the set stays: no node moves.
        for r in later.values_mut() {
            for a in r.values_mut() {
                a.tx *= 7.0;
            }
        }
        let b = layout(&later);
        let pos = |g: &Graph| g.nodes.iter().map(|n| (n.label.clone(), (n.x * 1e6).round(), (n.y * 1e6).round())).collect::<Vec<_>>();
        assert_eq!(pos(&a), pos(&b));
        assert_eq!(a.nodes[0].kind, Kind::Host);
        assert_eq!(a.nodes.len(), 1 + 3 + 6);
        assert_eq!(a.edges.len(), 6);
    }

    #[test]
    fn no_two_nodes_share_a_place() {
        let g = layout(&sample(MAX_PROCS, MAX_REMOTES + 3));
        for (i, a) in g.nodes.iter().enumerate() {
            for b in &g.nodes[i + 1..] {
                let d = ((a.x - b.x).powi(2) + (a.y - b.y).powi(2)).sqrt();
                assert!(d > 0.05, "{} and {} overlap", a.label, b.label);
            }
        }
    }

    #[test]
    fn quiet_remotes_and_processes_are_grouped() {
        let g = layout(&sample(MAX_PROCS + 2, MAX_REMOTES + 3));
        assert_eq!(g.hidden, 2);
        let more: Vec<&Node> = g.nodes.iter().filter(|n| n.kind == Kind::More).collect();
        assert_eq!(more.len(), MAX_PROCS);
        assert_eq!(more[0].label, "+3 more");
        assert_eq!(more[0].traffic.conns, 3);
        // Exactly one remote over the limit: shown, not "+1 more".
        let g = layout(&sample(1, MAX_REMOTES + 1));
        assert!(g.nodes.iter().all(|n| n.kind != Kind::More));
    }

    #[test]
    fn the_worst_verdict_colors_the_edge() {
        let mut a = agg(1.0);
        a.add(&Agg { verdict: Verdict::Deny, ..agg(1.0) });
        a.add(&Agg { verdict: Verdict::Ask, ..agg(1.0) });
        assert_eq!(a.verdict, Verdict::Deny);
        assert_eq!(a.conns, 3);
    }

    #[test]
    fn more_traffic_gives_more_and_faster_dots() {
        assert_eq!(dot_count(0.5), 0);
        assert_eq!(dot_count(50.0), 1);
        assert_eq!(dot_count(1e9), 4);
        assert!(speed(1e6) > speed(1e2));
        assert_eq!(speed(0.0), 0.0);
        assert!(dots_at(123.4, 3).iter().all(|d| (0.0..1.0).contains(d)));
        assert_eq!(dots_at(0.0, 2), vec![0.0, 0.5]);
    }

    #[test]
    fn a_new_rate_changes_speed_without_a_jump() {
        let mut m = Motion::default();
        m.step(0.1, 1e6, 0.0);
        assert!(m.up > 0.0 && m.up < 1e6, "eases toward the rate");
        let before = m.phase_up;
        m.step(0.1, 10.0, 0.0);
        let moved = (m.phase_up - before).rem_euclid(1.0);
        assert!(moved < 0.2, "one frame moves a short way: {moved}");
        for _ in 0..100 {
            m.step(0.1, 10.0, 0.0);
        }
        assert!((m.up - 10.0).abs() < 1.0, "reaches the new rate");
    }

    #[test]
    fn domains_keep_the_registrable_part() {
        assert_eq!(domain("a.b.example.com"), "example.com");
        assert_eq!(domain("news.bbc.co.uk."), "bbc.co.uk");
        assert_eq!(domain("localhost"), "localhost");
    }
}
