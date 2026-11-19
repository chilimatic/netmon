//! Turns cumulative kernel counters into per-flow rates and keeps history.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use netmon_common::{ConnState, FlowKey, FlowStats};

use crate::procmap::{ContainerTable, Listeners, Owner, SocketTable};

/// Ticks of history kept for the graphs.
pub const HISTORY: usize = 120;

pub use netmon_common::LOOPBACK_IFINDEX;

#[derive(Clone, Debug)]
pub struct Flow {
    pub key: FlowKey,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub total: FlowStats,
    /// Bytes per second.
    pub tx_rate: f64,
    pub rx_rate: f64,
    pub idle_ticks: u32,
    pub owner: Option<Owner>,
    /// Socket cookie the owner came from (kernel hooks). 0: owner is from
    /// /proc or unknown.
    pub owner_cookie: u64,
    pub owner_source: OwnerSource,
    pub state: &'static str,
    /// Direction and verdict the kernel holds for the connection. None
    /// while no rule or default deny is in force.
    pub conn: Option<ConnState>,
    /// Hostname of the remote end: the TLS server name of this connection,
    /// else the DNS name of the address.
    pub host: Option<String>,
    /// "tls" or "dns".
    pub host_source: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct IfaceStats {
    pub tx_rate: f64,
    pub rx_rate: f64,
    /// Bytes since netmon started. Grows only, also when flows expire.
    pub tx_total: u64,
    pub rx_total: u64,
    /// Combined bytes per second, oldest first.
    pub history: VecDeque<u64>,
}

#[derive(Clone)]
pub struct Collector {
    pub flows: HashMap<FlowKey, Flow>,
    pub ifaces: HashMap<u32, IfaceStats>,
    /// Total (tx, rx) bytes per second over all interfaces except loopback,
    /// oldest first.
    pub total_history: VecDeque<(f64, f64)>,
    /// Interfaces the totals count. Empty: every interface but loopback.
    pub counted: HashSet<u32>,
    expire_ticks: u32,
}

pub fn addr(family: u8, raw: &[u8; 16], port: u16) -> SocketAddr {
    let ip = if family == 4 {
        IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(*raw))
    };
    SocketAddr::new(ip, port)
}

impl Collector {
    pub fn new(expire_ticks: u32) -> Self {
        Collector {
            flows: HashMap::new(),
            ifaces: HashMap::new(),
            total_history: VecDeque::new(),
            counted: HashSet::new(),
            expire_ticks,
        }
    }

    /// Applies one snapshot of the kernel map taken `dt` seconds after the
    /// previous one. Returns flow keys idle for too long; the caller should
    /// delete them from the kernel map.
    pub fn ingest(
        &mut self,
        snapshot: impl IntoIterator<Item = (FlowKey, FlowStats)>,
        dt: f64,
    ) -> Vec<FlowKey> {
        let dt = dt.max(1e-3);
        let mut seen = HashSet::with_capacity(self.flows.len());
        // Per interface: tx and rx bytes in this interval.
        let mut deltas: HashMap<u32, (u64, u64)> = HashMap::new();
        for (key, cur) in snapshot {
            // Map iteration can return a key twice after an LRU eviction.
            // The second copy would have delta 0 and zero the rate.
            if !seen.insert(key) {
                continue;
            }
            let flow = self.flows.entry(key).or_insert_with(|| Flow {
                key,
                local: addr(key.family, &key.local_addr, key.local_port),
                remote: addr(key.family, &key.remote_addr, key.remote_port),
                total: FlowStats::default(),
                tx_rate: 0.0,
                rx_rate: 0.0,
                idle_ticks: 0,
                owner: None,
                owner_cookie: 0,
                owner_source: OwnerSource::Unknown,
                conn: None,
                host: None,
                host_source: "",
                state: "",
            });
            // A counter that went down means the LRU map evicted and
            // re-created the entry: count from zero.
            let delta = |now: u64, prev: u64| if now >= prev { now - prev } else { now };
            let dtx = delta(cur.tx_bytes, flow.total.tx_bytes);
            let drx = delta(cur.rx_bytes, flow.total.rx_bytes);
            flow.tx_rate = dtx as f64 / dt;
            flow.rx_rate = drx as f64 / dt;
            flow.idle_ticks = if dtx == 0 && drx == 0 { flow.idle_ticks + 1 } else { 0 };
            flow.total = cur;
            let d = deltas.entry(key.ifindex).or_default();
            d.0 += dtx;
            d.1 += drx;
        }
        self.flows.retain(|k, _| seen.contains(k));

        let expired: Vec<FlowKey> = self
            .flows
            .values()
            .filter(|f| f.idle_ticks >= self.expire_ticks)
            .map(|f| f.key)
            .collect();
        for k in &expired {
            self.flows.remove(k);
        }

        self.update_ifaces(&deltas, dt);
        expired
    }

    /// Rates come from this interval's bytes. Totals add them up, so they
    /// never go down when flows expire.
    fn update_ifaces(&mut self, deltas: &HashMap<u32, (u64, u64)>, dt: f64) {
        for (idx, &(dtx, drx)) in deltas {
            let st = self.ifaces.entry(*idx).or_default();
            st.tx_total += dtx;
            st.rx_total += drx;
        }
        let mut total = (0.0, 0.0);
        for (idx, st) in self.ifaces.iter_mut() {
            let (dtx, drx) = deltas.get(idx).copied().unwrap_or_default();
            st.tx_rate = dtx as f64 / dt;
            st.rx_rate = drx as f64 / dt;
            push(&mut st.history, (st.tx_rate + st.rx_rate) as u64);
            let counts = if self.counted.is_empty() { *idx != LOOPBACK_IFINDEX } else { self.counted.contains(idx) };
            if counts {
                total.0 += st.tx_rate;
                total.1 += st.rx_rate;
            }
        }
        push(&mut self.total_history, total);
    }

    /// Fills owner and state. Sources, best first: the kernel hooks by
    /// socket cookie (looked up once per cookie), the /proc socket with the
    /// exact 4-tuple, the kernel's record of who bound the local address
    /// (servers, UDP receivers), the /proc port guess. A weaker source never
    /// replaces a stronger one, so a closed socket keeps its owner.
    pub fn resolve(
        &mut self,
        table: &SocketTable,
        containers: &[ContainerTable],
        listeners: &Listeners,
        kernel: impl Fn(u64) -> Option<Owner>,
    ) {
        for f in self.flows.values_mut() {
            let cookie = f.total.cookie;
            if cookie != 0
                && cookie != f.owner_cookie
                && let Some(o) = kernel(cookie)
            {
                f.owner = Some(o);
                f.owner_cookie = cookie;
                f.owner_source = OwnerSource::Kernel;
            }
            let proc = table.lookup_kind(f.key.proto, f.local, f.remote);
            if f.owner_source < OwnerSource::Kernel {
                let proc_owner = proc.and_then(|(i, exact)| Some((i.owner.clone()?, exact)));
                let found = match proc_owner {
                    Some((o, true)) => Some((o, OwnerSource::ProcExact)),
                    _ => match listeners.lookup(f.key.proto, f.local) {
                        Some(o) => Some((o.clone(), OwnerSource::Listener)),
                        None => proc_owner.map(|(o, _)| (o, OwnerSource::ProcPort)),
                    },
                };
                if let Some((o, src)) = found
                    && src >= f.owner_source
                {
                    f.owner = Some(o);
                    f.owner_source = src;
                }
            }
            // Traffic of containers: no host socket, or only a guess by port.
            let mut container_state = None;
            if f.owner_source <= OwnerSource::Container
                && let Some((o, exact)) = containers.iter().find_map(|t| t.lookup(f.key.proto, f.local, f.remote))
            {
                f.owner = Some(o.clone());
                f.owner_source = OwnerSource::Container;
                if exact {
                    container_state = Some("container");
                }
            }
            f.state = match proc {
                _ if f.owner_source == OwnerSource::Container => container_state.unwrap_or("nat"),
                Some((i, _)) => i.state,
                None if f.owner.is_some() => "closed",
                None => "",
            };
        }
    }
}

/// Where a flow's owner came from, weakest first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum OwnerSource {
    #[default]
    Unknown,
    /// /proc socket matched by local port and bound address only.
    ProcPort,
    /// Socket of a container (other network namespace).
    Container,
    /// Kernel post_bind record of who bound the local address.
    Listener,
    /// /proc socket with the exact 4-tuple.
    ProcExact,
    /// Kernel hooks, by the socket cookie of the flow's own packets.
    Kernel,
}

impl OwnerSource {
    pub fn label(self) -> &'static str {
        match self {
            OwnerSource::Unknown => "",
            OwnerSource::ProcPort => "/proc (port)",
            OwnerSource::Container => "container /proc",
            OwnerSource::Listener => "kernel (bind)",
            OwnerSource::ProcExact => "/proc",
            OwnerSource::Kernel => "kernel",
        }
    }
}

fn push<T>(h: &mut VecDeque<T>, v: T) {
    if h.len() == HISTORY {
        h.pop_front();
    }
    h.push_back(v);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16, ifindex: u32) -> FlowKey {
        let mut k = FlowKey { family: 4, proto: 6, local_port: port, remote_port: 443, ifindex, ..Default::default() };
        k.local_addr[..4].copy_from_slice(&[10, 0, 0, 2]);
        k.remote_addr[..4].copy_from_slice(&[1, 1, 1, 1]);
        k
    }

    fn stats(tx: u64, rx: u64) -> FlowStats {
        FlowStats { tx_bytes: tx, rx_bytes: rx, ..Default::default() }
    }

    #[test]
    fn computes_rates_from_deltas() {
        let mut c = Collector::new(30);
        c.ingest([(key(1, 2), stats(100, 1000))], 1.0);
        c.ingest([(key(1, 2), stats(300, 5000))], 2.0);
        let f = &c.flows[&key(1, 2)];
        assert_eq!(f.tx_rate, 100.0);
        assert_eq!(f.rx_rate, 2000.0);
        assert_eq!(f.local.to_string(), "10.0.0.2:1");
        assert_eq!(f.remote.to_string(), "1.1.1.1:443");
    }

    #[test]
    fn counter_reset_counts_from_zero() {
        let mut c = Collector::new(30);
        c.ingest([(key(1, 2), stats(1000, 0))], 1.0);
        c.ingest([(key(1, 2), stats(50, 0))], 1.0);
        assert_eq!(c.flows[&key(1, 2)].tx_rate, 50.0);
    }

    #[test]
    fn expires_idle_flows_and_drops_missing() {
        let mut c = Collector::new(2);
        c.ingest([(key(1, 2), stats(1, 1)), (key(2, 2), stats(1, 1))], 1.0);
        assert!(c.ingest([(key(1, 2), stats(1, 1))], 1.0).is_empty());
        assert!(!c.flows.contains_key(&key(2, 2)), "missing flow dropped");
        let expired = c.ingest([(key(1, 2), stats(1, 1))], 1.0);
        assert_eq!(expired, vec![key(1, 2)]);
        assert!(c.flows.is_empty());
    }

    #[test]
    fn aggregates_per_interface_with_history() {
        let mut c = Collector::new(30);
        c.ingest([(key(1, 2), stats(0, 0)), (key(2, 2), stats(0, 0)), (key(3, 5), stats(0, 0))], 1.0);
        c.ingest([(key(1, 2), stats(10, 20)), (key(2, 2), stats(30, 40)), (key(3, 5), stats(1, 1))], 1.0);
        let s = &c.ifaces[&2];
        assert_eq!((s.tx_rate, s.rx_rate), (40.0, 60.0));
        assert_eq!(s.history.back(), Some(&100));
        assert_eq!(c.ifaces[&5].history.len(), 2);
        assert_eq!(c.total_history.back(), Some(&(41.0, 61.0)));
    }

    #[test]
    fn total_history_skips_loopback() {
        let mut c = Collector::new(30);
        c.ingest([(key(1, LOOPBACK_IFINDEX), stats(0, 0)), (key(2, 2), stats(0, 0))], 1.0);
        c.ingest([(key(1, LOOPBACK_IFINDEX), stats(500, 500)), (key(2, 2), stats(7, 9))], 1.0);
        assert_eq!(c.total_history.back(), Some(&(7.0, 9.0)));
        // With physical interfaces known, only they count.
        c.counted = HashSet::from([3]);
        c.ingest([(key(2, 2), stats(14, 18)), (key(3, 3), stats(0, 0))], 1.0);
        c.ingest([(key(2, 2), stats(20, 20)), (key(3, 3), stats(5, 6))], 1.0);
        assert_eq!(c.total_history.back(), Some(&(5.0, 6.0)));
    }

    #[test]
    fn duplicate_snapshot_key_is_ignored() {
        let mut c = Collector::new(30);
        c.ingest([(key(1, 2), stats(100, 0))], 1.0);
        c.ingest([(key(1, 2), stats(300, 0)), (key(1, 2), stats(300, 0))], 1.0);
        assert_eq!(c.flows[&key(1, 2)].tx_rate, 200.0);
        assert_eq!(c.ifaces[&2].tx_rate, 200.0);
    }

    #[test]
    fn interface_totals_survive_expiry() {
        let mut c = Collector::new(1);
        c.ingest([(key(1, 2), stats(100, 50))], 1.0);
        assert_eq!((c.ifaces[&2].tx_total, c.ifaces[&2].rx_total), (100, 50));
        // Idle: expires, but the bytes stay counted.
        c.ingest([(key(1, 2), stats(100, 50))], 1.0);
        assert!(c.flows.is_empty());
        c.ingest([(key(2, 2), stats(10, 0))], 1.0);
        assert_eq!((c.ifaces[&2].tx_total, c.ifaces[&2].rx_total), (110, 50));
        assert_eq!(c.ifaces[&2].tx_rate, 10.0);
    }

    #[test]
    fn long_interval_gives_average_rate() {
        let mut c = Collector::new(30);
        c.ingest([(key(1, 2), stats(0, 0))], 1.0);
        c.ingest([(key(1, 2), stats(6000, 0))], 60.0);
        assert_eq!(c.flows[&key(1, 2)].tx_rate, 100.0);
        assert_eq!(c.total_history.back(), Some(&(100.0, 0.0)));
    }

    #[test]
    fn kernel_owner_wins_over_proc() {
        use crate::procmap::RawSock;
        let mut c = Collector::new(30);
        let k = key(1, 2);
        c.ingest([(k, FlowStats { tx_bytes: 1, ..Default::default() })], 1.0);
        let table = SocketTable::build(
            vec![RawSock { proto: 6, local: "10.0.0.2:1".parse().unwrap(), remote: "1.1.1.1:443".parse().unwrap(), state: "ESTAB", inode: 9 }],
            &HashMap::from([(9, Owner::new(7, "proc"))]),
        );
        let kernel = |cookie: u64| (cookie == 77).then(|| Owner::new(8, "hook"));
        c.resolve(&table, &[], &Listeners::default(), kernel);
        assert_eq!(c.flows[&k].owner.as_ref().unwrap().pid, 7, "no cookie yet: /proc");
        c.ingest([(k, FlowStats { tx_bytes: 2, cookie: 77, ..Default::default() })], 1.0);
        c.resolve(&table, &[], &Listeners::default(), kernel);
        assert_eq!(c.flows[&k].owner.as_ref().unwrap().pid, 8, "cookie: kernel owner");
        assert_eq!(c.flows[&k].state, "ESTAB", "state still from /proc");
        c.resolve(&table, &[], &Listeners::default(), |_| unreachable!("looked up once per cookie"));
    }

    #[test]
    fn listener_owner_for_server_flows_and_no_downgrade() {
        use crate::procmap::RawSock;
        let mut c = Collector::new(30);
        // Inbound connection to a server on 10.0.0.2:1 (key local port 1).
        let k = key(1, 2);
        c.ingest([(k, FlowStats { rx_bytes: 1, ..Default::default() })], 1.0);
        let listeners = Listeners::build([(6, "0.0.0.0:1".parse().unwrap(), Owner::new(5, "server"))]);
        c.resolve(&SocketTable::default(), &[], &listeners, |_| None);
        let f = &c.flows[&k];
        assert_eq!((f.owner.as_ref().unwrap().pid, f.owner_source), (5, OwnerSource::Listener));
        // The exact /proc socket (a forked worker) is better.
        let table = SocketTable::build(
            vec![RawSock { proto: 6, local: "10.0.0.2:1".parse().unwrap(), remote: "1.1.1.1:443".parse().unwrap(), state: "ESTAB", inode: 9 }],
            &HashMap::from([(9, Owner::new(6, "worker"))]),
        );
        c.resolve(&table, &[], &listeners, |_| None);
        assert_eq!(c.flows[&k].owner.as_ref().unwrap().pid, 6);
        // Socket closed: only the listener is left; the worker stays.
        c.resolve(&SocketTable::default(), &[], &listeners, |_| None);
        let f = &c.flows[&k];
        assert_eq!((f.owner.as_ref().unwrap().pid, f.owner_source, f.state), (6, OwnerSource::ProcExact, "closed"));
    }
}

