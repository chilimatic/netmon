//! Loads the eBPF object, attaches the TC programs and reads the flow map.

use std::collections::HashSet;

use anyhow::{Context as _, bail};
use aya::{
    Ebpf, EbpfLoader, include_bytes_aligned,
    maps::{Array, HashMap, MapData, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{SchedClassifier, TcAttachType, tc},
    util::{KernelVersion, nr_cpus},
};
use netmon_common::{
    CAPTURE_FLOWS, CAPTURE_IFACE, CAPTURE_OFF, CaptureConfig, FlowKey, FlowStats, MAX_CAPTURE_FLOWS, MAX_FLOWS,
    PacketEvent,
};

use crate::ifaces::Iface;

static EBPF_OBJ: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/netmon"));

/// Kernel memory for the per-CPU flow counters, all CPUs together.
const FLOW_VALUE_BUDGET: usize = 64 * 1024 * 1024;
const MIN_FLOWS: u32 = 4_096;

/// Flow map size. Every entry holds one FlowStats per possible CPU, so the
/// size shrinks on hosts with many CPUs: 65 536 entries on up to 32 CPUs,
/// 16 384 on 128 CPUs.
pub fn flow_map_entries(cpus: usize) -> u32 {
    let per_entry = size_of::<FlowStats>() * cpus.max(1);
    let n = (FLOW_VALUE_BUDGET / per_entry).min(MAX_FLOWS as usize) as u32;
    n.max(MIN_FLOWS)
}

/// Kernels before 6.6 have no tcx; TC programs then need a clsact qdisc.
fn needs_clsact() -> bool {
    KernelVersion::current().map(|v| v < KernelVersion::new(6, 6, 0)).unwrap_or(true)
}

pub struct Probe {
    ebpf: Ebpf,
    flows: PerCpuHashMap<MapData, FlowKey, FlowStats>,
    l3_offset: HashMap<MapData, u32, u32>,
    capture_cfg: Array<MapData, CaptureConfig>,
    capture_keys: HashMap<MapData, FlowKey, u8>,
    capture_set: HashSet<FlowKey>,
    /// The last capture key update did not fit in the kernel map.
    capture_full: bool,
    packets: RingBuf<MapData>,
    drops: PerCpuArray<MapData, u64>,
    attached: HashSet<u32>,
    failed: HashSet<u32>,
}

impl Probe {
    pub fn load() -> anyhow::Result<Self> {
        if EBPF_OBJ.is_empty() {
            bail!("binary was built with AYA_BUILD_SKIP=1 and has no eBPF object; rebuild without it");
        }
        let cpus = nr_cpus().map_err(|(path, e)| anyhow::anyhow!("read {path}: {e}"))?;
        let mut ebpf = EbpfLoader::new()
            .map_max_entries("FLOWS", flow_map_entries(cpus))
            .load(EBPF_OBJ)
            .context("load eBPF object (run as root or with CAP_BPF + CAP_NET_ADMIN)")?;
        for name in ["tc_ingress", "tc_egress"] {
            let prog: &mut SchedClassifier = ebpf
                .program_mut(name)
                .with_context(|| format!("program {name} missing"))?
                .try_into()?;
            prog.load().with_context(|| format!("load {name}"))?;
        }
        let flows = PerCpuHashMap::try_from(ebpf.take_map("FLOWS").context("map FLOWS missing")?)?;
        let l3_offset = HashMap::try_from(ebpf.take_map("L3_OFFSET").context("map L3_OFFSET missing")?)?;
        let mut take = |name: &str| ebpf.take_map(name).with_context(|| format!("map {name} missing"));
        let capture_cfg = Array::try_from(take("CAPTURE_CFG")?)?;
        let capture_keys = HashMap::try_from(take("CAPTURE_KEYS")?)?;
        let packets = RingBuf::try_from(take("PACKETS")?)?;
        let drops = PerCpuArray::try_from(take("CAPTURE_DROPS")?)?;
        Ok(Probe {
            ebpf,
            flows,
            l3_offset,
            capture_cfg,
            capture_keys,
            capture_set: HashSet::new(),
            capture_full: false,
            packets,
            drops,
            attached: HashSet::new(),
            failed: HashSet::new(),
        })
    }

    /// Attaches to interfaces not seen before. Returns errors for new
    /// failures only, so a broken interface is reported once.
    pub fn attach_new(&mut self, ifaces: &[Iface]) -> Vec<String> {
        let mut errors = Vec::new();
        let live: HashSet<u32> = ifaces.iter().map(|i| i.index).collect();
        // Interface indexes of removed devices can be reused: forget them,
        // with their L3 offset.
        for gone in self.attached.iter().chain(&self.failed).filter(|i| !live.contains(i)) {
            let _ = self.l3_offset.remove(gone);
        }
        self.attached.retain(|i| live.contains(i));
        self.failed.retain(|i| live.contains(i));
        for iface in ifaces {
            if self.attached.contains(&iface.index) || self.failed.contains(&iface.index) {
                continue;
            }
            match self.attach(iface) {
                Ok(()) => {
                    self.attached.insert(iface.index);
                }
                Err(e) => {
                    self.failed.insert(iface.index);
                    errors.push(format!("{}: {e:#}", iface.name));
                }
            }
        }
        errors
    }

    fn attach(&mut self, iface: &Iface) -> anyhow::Result<()> {
        // Missing means 14 (Ethernet). Set or clear it, so a reused index
        // never keeps the offset of an old device.
        if iface.l3_offset != 14 {
            self.l3_offset.insert(iface.index, iface.l3_offset, 0)?;
        } else {
            let _ = self.l3_offset.remove(&iface.index);
        }
        if needs_clsact() {
            // Fails if the qdisc exists, which is fine. A real failure shows
            // up in the attach below.
            let _ = tc::qdisc_add_clsact(&iface.name);
        }
        for (name, ty) in [("tc_ingress", TcAttachType::Ingress), ("tc_egress", TcAttachType::Egress)] {
            let prog: &mut SchedClassifier = self.ebpf.program_mut(name).context("program missing")?.try_into()?;
            prog.attach(&iface.name, ty)?;
        }
        Ok(())
    }

    pub fn attached_count(&self) -> usize {
        self.attached.len()
    }

    /// Current counters, summed over all CPUs.
    pub fn snapshot(&self) -> Vec<(FlowKey, FlowStats)> {
        self.flows
            .iter()
            .flatten()
            .map(|(k, per_cpu)| {
                let mut sum = FlowStats::default();
                for s in per_cpu.iter() {
                    sum.tx_bytes += s.tx_bytes;
                    sum.rx_bytes += s.rx_bytes;
                    sum.tx_pkts += s.tx_pkts;
                    sum.rx_pkts += s.rx_pkts;
                }
                (k, sum)
            })
            .collect()
    }

    /// Captures every packet on one interface.
    pub fn capture_iface(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.set_capture_keys(&HashSet::new())?;
        self.capture_cfg.set(0, CaptureConfig { mode: CAPTURE_IFACE, ifindex }, 0)?;
        Ok(())
    }

    /// Captures packets of the given flows. Call again to update the set.
    pub fn capture_flows(&mut self, keys: &HashSet<FlowKey>) -> anyhow::Result<()> {
        self.set_capture_keys(keys)?;
        self.capture_cfg.set(0, CaptureConfig { mode: CAPTURE_FLOWS, ifindex: 0 }, 0)?;
        Ok(())
    }

    /// Stops capturing. Packets already in the ring stay there for
    /// `drain_packets`; call `discard_packets` to drop them.
    pub fn capture_off(&mut self) -> anyhow::Result<()> {
        self.capture_cfg.set(0, CaptureConfig { mode: CAPTURE_OFF, ifindex: 0 }, 0)?;
        self.set_capture_keys(&HashSet::new())
    }

    pub fn discard_packets(&mut self) {
        while self.packets.next().is_some() {}
    }

    /// Makes the kernel key set equal to `capture_set`, which always
    /// mirrors what is really in the map. Keys over MAX_CAPTURE_FLOWS are
    /// left out. That is reported once, not on every update.
    fn set_capture_keys(&mut self, keys: &HashSet<FlowKey>) -> anyhow::Result<()> {
        let gone: Vec<FlowKey> = self.capture_set.difference(keys).copied().collect();
        for k in gone {
            // Delete fails only if the key is missing, which is the goal.
            let _ = self.capture_keys.remove(&k);
            self.capture_set.remove(&k);
        }
        let mut skipped = 0;
        let mut error = None;
        for k in keys.difference(&self.capture_set.clone()) {
            if self.capture_set.len() >= MAX_CAPTURE_FLOWS as usize {
                skipped += 1;
                continue;
            }
            match self.capture_keys.insert(k, 1, 0) {
                Ok(()) => {
                    self.capture_set.insert(*k);
                }
                Err(e) => {
                    skipped += 1;
                    error.get_or_insert(e);
                }
            }
        }
        let was_full = std::mem::replace(&mut self.capture_full, skipped > 0);
        if skipped == 0 || was_full {
            return Ok(());
        }
        match error {
            Some(e) => Err(anyhow::Error::new(e).context(format!("{skipped} flows not captured"))),
            None => bail!("{skipped} flows not captured: limit is {MAX_CAPTURE_FLOWS}"),
        }
    }

    /// Takes up to `max` captured packets from the ring buffer.
    pub fn drain_packets(&mut self, max: usize, mut f: impl FnMut(&PacketEvent)) {
        for _ in 0..max {
            let Some(item) = self.packets.next() else { break };
            if item.len() >= size_of::<PacketEvent>() {
                // SAFETY: the kernel wrote a PacketEvent; the read is unaligned-safe.
                let ev = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const PacketEvent) };
                f(&ev);
            }
        }
    }

    /// Packets lost because the ring buffer was full, since load. Callers
    /// subtract the value at capture start.
    pub fn capture_drops(&self) -> u64 {
        self.drops.get(&0, 0).map(|v| v.iter().sum()).unwrap_or(0)
    }

    pub fn forget(&mut self, keys: &[FlowKey]) {
        for k in keys {
            let _ = self.flows.remove(k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_map_shrinks_with_cpus() {
        assert_eq!(flow_map_entries(1), MAX_FLOWS);
        assert_eq!(flow_map_entries(32), 65_536);
        assert_eq!(flow_map_entries(128), 16_384);
        assert_eq!(flow_map_entries(100_000), MIN_FLOWS);
        // Values never exceed the budget, except at the minimum size.
        for cpus in [1, 8, 64, 256, 1024] {
            let n = flow_map_entries(cpus) as usize;
            assert!(n * cpus * size_of::<FlowStats>() <= FLOW_VALUE_BUDGET || n == MIN_FLOWS as usize);
        }
    }
}
