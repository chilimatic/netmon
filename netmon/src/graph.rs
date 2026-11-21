//! The connection graph: this host in the middle, processes on a ring
//! around it, remote ends on an outer ring. Only the model and the layout
//! are here. ui.rs draws them.

use std::{collections::BTreeMap, f64::consts::TAU};

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
pub fn groups(c: &Collector, names: &Names, show_virtual: bool, show_hosts: bool) -> Groups {
    let mut out = Groups::new();
    for f in c.flows.values().filter(|f| show_virtual || !names.kind(f.key.ifindex).is_virtual()) {
        let (process, _) = owner_cols(f);
        let remote = f.host.clone().filter(|_| show_hosts).unwrap_or_else(|| f.remote.ip().to_string());
        let a = Agg {
            tx: f.tx_rate,
            rx: f.rx_rate,
            conns: 1,
            verdict: f.conn.map_or(Verdict::None, |s| Verdict::of(s.action)),
        };
        out.entry(process).or_default().entry(remote).or_default().add(&a);
    }
    out
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
    g.nodes.push(Node { kind: Kind::Host, label: "this host".into(), x: 0.0, y: 0.0, traffic: host });
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
            g.nodes.push(Node { kind, label, x: REMOTE_RING * a.cos(), y: REMOTE_RING * a.sin(), traffic });
            g.edges.push(Edge { from: p, to: r, traffic });
        }
    }
    g
}

/// Where the dots of one direction are at time `t` (seconds), as
/// fractions 0..1 along the edge. More bytes per second give more and
/// faster dots, on a log scale. Below 1 B/s there are none.
pub fn dots(rate: f64, t: f64) -> Vec<f64> {
    if rate < 1.0 {
        return Vec::new();
    }
    let lg = rate.log10();
    let n = (lg / 2.0).ceil().clamp(1.0, 4.0) as usize;
    let speed = 0.15 + 0.08 * lg;
    (0..n).map(|i| (t * speed + i as f64 / n as f64).fract()).collect()
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
        assert!(dots(0.5, 1.0).is_empty());
        assert_eq!(dots(50.0, 0.0).len(), 1);
        assert_eq!(dots(1e9, 0.0).len(), 4);
        let step = |rate: f64| dots(rate, 1.0)[0] - dots(rate, 0.0)[0];
        assert!(step(1e6) > step(1e2));
        assert!(dots(1e6, 123.4).iter().all(|d| (0.0..1.0).contains(d)));
    }
}
