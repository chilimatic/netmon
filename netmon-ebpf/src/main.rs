#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_NOEXIST, TC_ACT_UNSPEC, __sk_buff},
    cty::c_void,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_skb_load_bytes,
    },
    macros::{cgroup_sock, cgroup_sock_addr, classifier, map},
    maps::{Array, HashMap, LruHashMap, LruPerCpuHashMap, PerCpuArray, RingBuf},
    programs::{SockAddrContext, SockContext, TcContext},
};
use netmon_common::{
    CAPTURE_FLOWS, CAPTURE_IFACE, CAPTURE_LEN, CAPTURE_RING_BYTES, CaptureConfig, FlowKey,
    FlowStats, IPPROTO_TCP, IPPROTO_UDP, LOOPBACK_IFINDEX, ListenKey, ListenOwner,
    MAX_CAPTURE_FLOWS, MAX_FLOWS, MAX_IFACES, MAX_LISTENERS, MAX_SOCK_OWNERS, PacketEvent,
    PacketSource, SockOwner, parse_packet,
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

/// Socket cookie -> process that created or last used the socket.
/// Monitoring only, so LRU is fine: an evicted entry falls back to /proc.
#[map]
static SOCK_OWNER: LruHashMap<u64, SockOwner> = LruHashMap::with_max_entries(MAX_SOCK_OWNERS, 0);

/// Bound sockets (servers, UDP receivers) -> owner, from post_bind.
#[map]
static LISTENERS: LruHashMap<ListenKey, ListenOwner> = LruHashMap::with_max_entries(MAX_LISTENERS, 0);

/// Socket cookie -> its LISTENERS key, so sock_release can find the entry:
/// the release hook may not read the socket's address.
#[map]
static LISTEN_BY_COOKIE: LruHashMap<u64, ListenKey> = LruHashMap::with_max_entries(MAX_LISTENERS, 0);

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
    // Every loopback packet passes egress and then ingress. Capture it once,
    // on egress. The ingress side of the flow is the reversed key.
    let lo = ifindex == LOOPBACK_IFINDEX;
    if lo && !egress {
        return;
    }
    let hit = match cfg.mode {
        CAPTURE_IFACE => cfg.ifindex == ifindex,
        CAPTURE_FLOWS => match &key {
            Some(k) => unsafe {
                CAPTURE_KEYS.get(k).is_some() || (lo && CAPTURE_KEYS.get(&k.reversed()).is_some())
            },
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
    // Locally sent packets carry their socket. 0 for forwarded traffic.
    let cookie = if egress { unsafe { bpf_get_socket_cookie(ctx.as_ptr()) } } else { 0 };
    // Per-CPU values: no other CPU writes this slot, so plain adds are safe.
    if let Some(s) = FLOWS.get_ptr_mut(key) {
        let s = unsafe { &mut *s };
        if egress {
            s.tx_bytes += len;
            s.tx_pkts += 1;
            if cookie != 0 {
                s.cookie = cookie;
            }
        } else {
            s.rx_bytes += len;
            s.rx_pkts += 1;
        }
    } else {
        let s = if egress {
            FlowStats { tx_bytes: len, tx_pkts: 1, cookie, ..Default::default() }
        } else {
            FlowStats { rx_bytes: len, rx_pkts: 1, ..Default::default() }
        };
        // Two CPUs can see a new flow at the same time. A plain insert would
        // replace the other CPU's entry and lose its count. With NOEXIST the
        // second insert fails and that CPU adds to its own slot instead.
        if FLOWS.insert(key, &s, BPF_NOEXIST as u64).is_err()
            && let Some(p) = FLOWS.get_ptr_mut(key)
        {
            let p = unsafe { &mut *p };
            p.tx_bytes += s.tx_bytes;
            p.tx_pkts += s.tx_pkts;
            p.rx_bytes += s.rx_bytes;
            p.rx_pkts += s.rx_pkts;
            if cookie != 0 {
                p.cookie = cookie;
            }
        }
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

// Socket owner hooks on the root cgroup. They run in the context of the
// process that creates or uses the socket. They only record and must always
// return 1: 0 would deny the socket call with EPERM.

const ALLOW: i32 = 1;

/// Writes the current process as owner of the socket behind `ctx`. Skips the
/// write when the entry already names this process, so busy UDP senders do
/// not rewrite it on every datagram.
#[inline(always)]
fn record_owner(ctx: *mut c_void) {
    let cookie = unsafe { bpf_get_socket_cookie(ctx) };
    if cookie == 0 {
        return;
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(o) = unsafe { SOCK_OWNER.get(&cookie) }
        && o.tgid == tgid
    {
        return;
    }
    let _ = SOCK_OWNER.insert(&cookie, &current_owner(tgid), 0);
}

#[inline(always)]
fn current_owner(tgid: u32) -> SockOwner {
    SockOwner {
        tgid,
        uid: bpf_get_current_uid_gid() as u32,
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
    }
}

/// Records the owner of a bound TCP or UDP socket under its bound address.
#[inline(always)]
fn record_bind(ctx: &SockContext, family: u8) {
    let sk = ctx.sock;
    let proto = unsafe { (*sk).protocol } as u8;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return;
    }
    let mut key = ListenKey { proto, family, port: unsafe { (*sk).src_port } as u16, ..Default::default() };
    // Each post_bind type may read only its own family's address field.
    // The fields hold network byte order, so native-order bytes are the
    // address bytes.
    if family == 4 {
        key.addr[..4].copy_from_slice(&unsafe { (*sk).src_ip4 }.to_ne_bytes());
    } else {
        let ip6 = unsafe { (*sk).src_ip6 };
        let mut i = 0;
        while i < 4 {
            key.addr[i * 4..i * 4 + 4].copy_from_slice(&ip6[i].to_ne_bytes());
            i += 1;
        }
    }
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let value = ListenOwner { owner: current_owner(tgid), cookie };
    let _ = LISTENERS.insert(&key, &value, 0);
    let _ = LISTEN_BY_COOKIE.insert(&cookie, &key, 0);
}

#[cgroup_sock(post_bind4)]
pub fn post_bind4(ctx: SockContext) -> i32 {
    record_bind(&ctx, 4);
    ALLOW
}

#[cgroup_sock(post_bind6)]
pub fn post_bind6(ctx: SockContext) -> i32 {
    record_bind(&ctx, 6);
    ALLOW
}

/// Removes the listener entry of a closed bound socket, unless another
/// socket has bound the same address since.
#[cgroup_sock(sock_release)]
pub fn sock_release(ctx: SockContext) -> i32 {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    if let Some(key) = unsafe { LISTEN_BY_COOKIE.get(&cookie) } {
        let key = *key;
        if let Some(v) = unsafe { LISTENERS.get(&key) }
            && v.cookie == cookie
        {
            let _ = LISTENERS.remove(&key);
        }
        let _ = LISTEN_BY_COOKIE.remove(&cookie);
    }
    ALLOW
}

#[cgroup_sock(sock_create)]
pub fn sock_create(ctx: SockContext) -> i32 {
    record_owner(ctx.as_ptr());
    ALLOW
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    record_owner(ctx.as_ptr());
    ALLOW
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    record_owner(ctx.as_ptr());
    ALLOW
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    record_owner(ctx.as_ptr());
    ALLOW
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    record_owner(ctx.as_ptr());
    ALLOW
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
