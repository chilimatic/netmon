//! Turns cumulative kernel counters into per-flow rates and keeps history.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use netmon_common::{FlowKey, FlowStats};

use crate::procmap::{Owner, SocketTable};

/// Ticks of history kept for the graphs.
pub const HISTORY: usize = 120;

/// The loopback device always has ifindex 1 on Linux.
pub const LOOPBACK_IFINDEX: u32 = 1;

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
    pub state: &'static str,
}

#[derive(Clone, Debug, Default)]
pub struct IfaceStats {
    pub tx_rate: f64,
    pub rx_rate: f64,
    pub tx_total: u64,
    pub rx_total: u64,
    /// Combined bytes per second, oldest first.
    pub history: VecDeque<u64>,
}

pub struct Collector {
    pub flows: HashMap<FlowKey, Flow>,
    pub ifaces: HashMap<u32, IfaceStats>,
    /// Total (tx, rx) bytes per second over all interfaces except loopback,
    /// oldest first.
    pub total_history: VecDeque<(f64, f64)>,
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
        Collector { flows: HashMap::new(), ifaces: HashMap::new(), total_history: VecDeque::new(), expire_ticks }
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
        let mut seen = HashMap::with_capacity(self.flows.len());
        for (key, cur) in snapshot {
            seen.insert(key, ());
            let flow = self.flows.entry(key).or_insert_with(|| Flow {
                key,
                local: addr(key.family, &key.local_addr, key.local_port),
                remote: addr(key.family, &key.remote_addr, key.remote_port),
                total: FlowStats::default(),
                tx_rate: 0.0,
                rx_rate: 0.0,
                idle_ticks: 0,
                owner: None,
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
        }
        self.flows.retain(|k, _| seen.contains_key(k));

        let expired: Vec<FlowKey> = self
            .flows
            .values()
            .filter(|f| f.idle_ticks >= self.expire_ticks)
            .map(|f| f.key)
            .collect();
        for k in &expired {
            self.flows.remove(k);
        }

        self.update_ifaces();
        expired
    }

    fn update_ifaces(&mut self) {
        let mut sums: HashMap<u32, (f64, f64, u64, u64)> = HashMap::new();
        for f in self.flows.values() {
            let s = sums.entry(f.key.ifindex).or_default();
            s.0 += f.tx_rate;
            s.1 += f.rx_rate;
            s.2 += f.total.tx_bytes;
            s.3 += f.total.rx_bytes;
        }
        for (idx, st) in self.ifaces.iter_mut() {
            if !sums.contains_key(idx) {
                st.tx_rate = 0.0;
                st.rx_rate = 0.0;
                push(&mut st.history, 0);
            }
        }
        let total = sums
            .iter()
            .filter(|(idx, _)| **idx != LOOPBACK_IFINDEX)
            .fold((0.0, 0.0), |(t, r), (_, s)| (t + s.0, r + s.1));
        push(&mut self.total_history, total);
        for (idx, (tx, rx, txt, rxt)) in sums {
            let st = self.ifaces.entry(idx).or_default();
            st.tx_rate = tx;
            st.rx_rate = rx;
            st.tx_total = txt;
            st.rx_total = rxt;
            push(&mut st.history, (tx + rx) as u64);
        }
    }

    /// Fills owner and state from the socket table. Keeps the last known
    /// owner when the socket is already gone.
    pub fn resolve(&mut self, table: &SocketTable) {
        for f in self.flows.values_mut() {
            match table.lookup(f.key.proto, f.local, f.remote) {
                Some(info) => {
                    if info.owner.is_some() {
                        f.owner = info.owner.clone();
                    }
                    f.state = info.state;
                }
                None => f.state = if f.owner.is_some() { "closed" } else { "" },
            }
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
    }
}
