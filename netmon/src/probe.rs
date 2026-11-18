//! Loads the eBPF object, attaches the TC programs and reads the flow map.

use std::collections::HashSet;

use anyhow::{Context as _, bail};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, HashMap, MapData, PerCpuArray, PerCpuHashMap, RingBuf},
    programs::{SchedClassifier, TcAttachType},
};
use netmon_common::{CAPTURE_FLOWS, CAPTURE_IFACE, CAPTURE_OFF, CaptureConfig, FlowKey, FlowStats, PacketEvent};

use crate::ifaces::Iface;

static EBPF_OBJ: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/netmon"));

pub struct Probe {
    ebpf: Ebpf,
    flows: PerCpuHashMap<MapData, FlowKey, FlowStats>,
    l3_offset: HashMap<MapData, u32, u32>,
    capture_cfg: Array<MapData, CaptureConfig>,
    capture_keys: HashMap<MapData, FlowKey, u8>,
    capture_set: HashSet<FlowKey>,
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
        let mut ebpf = Ebpf::load(EBPF_OBJ).context("load eBPF object (run as root or with CAP_BPF + CAP_NET_ADMIN)")?;
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
        // Interface indexes of removed devices can be reused.
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
        if iface.l3_offset != 14 {
            self.l3_offset.insert(iface.index, iface.l3_offset, 0)?;
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

    pub fn capture_off(&mut self) -> anyhow::Result<()> {
        self.capture_cfg.set(0, CaptureConfig { mode: CAPTURE_OFF, ifindex: 0 }, 0)?;
        self.set_capture_keys(&HashSet::new())?;
        // Drop packets still queued from the old capture.
        while self.packets.next().is_some() {}
        Ok(())
    }

    fn set_capture_keys(&mut self, keys: &HashSet<FlowKey>) -> anyhow::Result<()> {
        for k in self.capture_set.difference(keys) {
            let _ = self.capture_keys.remove(k);
        }
        for k in keys.difference(&self.capture_set) {
            self.capture_keys.insert(k, 1, 0)?;
        }
        self.capture_set = keys.clone();
        Ok(())
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

    /// Packets lost because the ring buffer was full, since load.
    pub fn capture_drops(&self) -> u64 {
        self.drops.get(&0, 0).map(|v| v.iter().sum()).unwrap_or(0)
    }

    pub fn forget(&mut self, keys: &[FlowKey]) {
        for k in keys {
            let _ = self.flows.remove(k);
        }
    }
}
