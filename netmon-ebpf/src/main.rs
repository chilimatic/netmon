#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{TC_ACT_UNSPEC, __sk_buff},
    cty::c_void,
    helpers::{bpf_ktime_get_ns, bpf_skb_load_bytes},
    macros::{classifier, map},
    maps::{Array, HashMap, LruPerCpuHashMap, PerCpuArray, RingBuf},
    programs::TcContext,
};
use netmon_common::{
    CAPTURE_FLOWS, CAPTURE_IFACE, CAPTURE_LEN, CAPTURE_RING_BYTES, CaptureConfig, FlowKey,
    FlowStats, MAX_CAPTURE_FLOWS, MAX_FLOWS, MAX_IFACES, PacketEvent, PacketSource,
    parse_packet,
};

/// Byte counters per flow and interface.
#[map]
static FLOWS: LruPerCpuHashMap<FlowKey, FlowStats> =
    LruPerCpuHashMap::with_max_entries(MAX_FLOWS, 0);

/// ifindex -> offset of the IP header. Userspace sets 0 for devices
/// without a link-layer header (tun, wireguard). Missing means 14 (Ethernet).
#[map]
static L3_OFFSET: HashMap<u32, u32> = HashMap::with_max_entries(MAX_IFACES, 0);

/// What to capture. Index 0 only. Mode CAPTURE_OFF costs one lookup.
#[map]
static CAPTURE_CFG: Array<CaptureConfig> = Array::with_max_entries(1, 0);

/// Flow keys to capture in CAPTURE_FLOWS mode (process or connection).
#[map]
static CAPTURE_KEYS: HashMap<FlowKey, u8> = HashMap::with_max_entries(MAX_CAPTURE_FLOWS, 0);

/// Captured packets for userspace.
#[map]
static PACKETS: RingBuf = RingBuf::with_byte_size(CAPTURE_RING_BYTES, 0);

/// Packets lost because the ring buffer was full. Index 0 only.
#[map]
static CAPTURE_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

struct Skb<'a>(&'a TcContext);

impl PacketSource for Skb<'_> {
    #[inline(always)]
    fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        self.0.load::<[u8; N]>(offset).ok()
    }
}

// The programs only observe. They return TC_ACT_UNSPEC (TCX_NEXT), which
// lets the next program on the hook run. TC_ACT_OK would be TCX_PASS and
// would skip every tcx program attached after netmon.

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    handle(&ctx, true);
    TC_ACT_UNSPEC
}

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    handle(&ctx, false);
    TC_ACT_UNSPEC
}

#[inline(always)]
fn handle(ctx: &TcContext, egress: bool) {
    let skb = ctx.as_ptr() as *const __sk_buff;
    let ifindex = unsafe { (*skb).ifindex };
    // skb->protocol holds a big-endian u16.
    let ethertype = u16::from_be(ctx.skb.protocol() as u16);
    let l3 = unsafe { L3_OFFSET.get(&ifindex) }.copied().unwrap_or(14);

    let key = parse_packet(&Skb(ctx), l3 as usize, ethertype)
        .map(|pkt| FlowKey::from_packet(&pkt, ifindex, egress));
    if let Some(key) = &key {
        count(ctx, key, egress);
    }

    let Some(cfg) = CAPTURE_CFG.get(0) else { return };
    let hit = match cfg.mode {
        CAPTURE_IFACE => cfg.ifindex == ifindex,
        CAPTURE_FLOWS => match &key {
            Some(k) => unsafe { CAPTURE_KEYS.get(k) }.is_some(),
            None => false,
        },
        _ => false,
    };
    if hit {
        capture(ctx, ifindex, ethertype, l3 != 0, egress);
    }
}

#[inline(always)]
fn count(ctx: &TcContext, key: &FlowKey, egress: bool) {
    let len = ctx.len() as u64;
    // Per-CPU values: no other CPU writes this slot, so plain adds are safe.
    if let Some(s) = FLOWS.get_ptr_mut(key) {
        let s = unsafe { &mut *s };
        if egress {
            s.tx_bytes += len;
            s.tx_pkts += 1;
        } else {
            s.rx_bytes += len;
            s.rx_pkts += 1;
        }
    } else {
        let s = if egress {
            FlowStats { tx_bytes: len, tx_pkts: 1, ..Default::default() }
        } else {
            FlowStats { rx_bytes: len, rx_pkts: 1, ..Default::default() }
        };
        let _ = FLOWS.insert(key, &s, 0);
    }
}

/// Copies up to CAPTURE_LEN bytes of the packet into the ring buffer.
#[inline(always)]
fn capture(ctx: &TcContext, ifindex: u32, ethertype: u16, has_l2: bool, egress: bool) {
    let Some(mut entry) = PACKETS.reserve::<PacketEvent>(0) else {
        if let Some(d) = CAPTURE_DROPS.get_ptr_mut(0) {
            unsafe { *d += 1 };
        }
        return;
    };
    let len = ctx.len();
    // The verifier needs the copy length proven to be in 1..=CAPTURE_LEN.
    let mut n = len;
    if n > CAPTURE_LEN as u32 {
        n = CAPTURE_LEN as u32;
    }
    if n == 0 {
        entry.discard(0);
        return;
    }
    let ev = entry.as_mut_ptr();
    let ret = unsafe {
        bpf_skb_load_bytes(ctx.as_ptr() as *const c_void, 0, (*ev).data.as_mut_ptr() as *mut c_void, n)
    };
    if ret != 0 {
        entry.discard(0);
        return;
    }
    unsafe {
        (*ev).ts_ns = bpf_ktime_get_ns();
        (*ev).ifindex = ifindex;
        (*ev).len = len;
        (*ev).cap_len = n;
        (*ev).ethertype = ethertype;
        (*ev).egress = egress as u8;
        (*ev).has_l2 = has_l2 as u8;
    }
    entry.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
