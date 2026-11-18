#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_NOEXIST, TC_ACT_SHOT, TC_ACT_UNSPEC, __sk_buff},
    cty::c_void,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_get_socket_cookie, bpf_ktime_get_ns,
        bpf_probe_read_kernel_str_bytes, bpf_skb_load_bytes,
    },
    macros::{cgroup_sock, cgroup_sock_addr, classifier, map, tracepoint},
    maps::{Array, HashMap, LpmTrie, LruHashMap, LruPerCpuHashMap, PerCpuArray, RingBuf, lpm_trie::Key},
    programs::{SockAddrContext, SockContext, TcContext, TracePointContext},
};
use netmon_common::{
    CAPTURE_FLOWS, CAPTURE_IFACE, CAPTURE_LEN, CAPTURE_RING_BYTES, CaptureConfig, FlowKey,
    FlowStats, GuardKey, IPPROTO_TCP, IPPROTO_UDP, LOOPBACK_IFINDEX, ListenKey, ListenOwner,
    MAX_BLOCKED_TGIDS, MAX_CAPTURE_FLOWS, MAX_EXE_PATH, MAX_FLOWS, MAX_GUARD, MAX_IFACES,
    MAX_LISTENERS, MAX_RULES, MAX_SOCK_OWNERS, PacketEvent, PacketSource, PortKey, SockOwner,
    TraceCfg, is_loopback, parse_packet,
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

// Block rules. Verdict maps are never LRU: an evicted rule would silently
// stop blocking. Userspace keeps them; they end with the process (fail-open).

/// Remote IPv4 networks to block -> rule id.
#[map]
static BLOCK_V4: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(MAX_RULES, 0);

/// Remote IPv6 networks to block -> rule id.
#[map]
static BLOCK_V6: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(MAX_RULES, 0);

/// Remote ports to block -> rule id.
#[map]
static BLOCK_PORT: HashMap<PortKey, u32> = HashMap::with_max_entries(MAX_RULES, 0);

/// Number of rules. 0 skips every lookup. Index 0 only.
#[map]
static RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// Remote endpoints that are never blocked (lockout guard).
#[map]
static GUARD: HashMap<GuardKey, u8> = HashMap::with_max_entries(MAX_GUARD, 0);

/// Exe paths to block (NUL-padded) -> rule id.
#[map]
static BLOCK_EXE: HashMap<[u8; MAX_EXE_PATH], u32> = HashMap::with_max_entries(MAX_RULES, 0);

/// Blocked processes (tgid) -> rule id. Set by the exec and fork
/// tracepoints and by userspace for processes that already run.
#[map]
static BLOCK_TGID: HashMap<u32, u32> = HashMap::with_max_entries(MAX_BLOCKED_TGIDS, 0);

/// Tracepoint field offsets from userspace. Index 0 only.
#[map]
static TRACE_CFG: Array<TraceCfg> = Array::with_max_entries(1, 0);

/// Packets and socket calls stopped, per rule id.
#[map]
static RULE_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(MAX_RULES, 0);

/// The rule that blocks traffic of process `tgid` (0: unknown) to
/// `addr`:`port`, if any. Loopback and guarded endpoints always pass.
#[inline(always)]
fn verdict(family: u8, addr: &[u8; 16], proto: u8, port: u16, tgid: u32) -> Option<u32> {
    if RULE_COUNT.get(0).copied().unwrap_or(0) == 0 || is_loopback(family, addr) {
        return None;
    }
    let guard = GuardKey { addr: *addr, port, family, _pad: 0 };
    if unsafe { GUARD.get(&guard) }.is_some() {
        return None;
    }
    let net = if family == 4 {
        BLOCK_V4.get(&Key::new(32, [addr[0], addr[1], addr[2], addr[3]]))
    } else {
        BLOCK_V6.get(&Key::new(128, *addr))
    };
    if let Some(id) = net {
        return Some(*id);
    }
    if port != 0
        && (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
        && let Some(id) = unsafe { BLOCK_PORT.get(&PortKey { port, proto, _pad: 0 }) }
    {
        return Some(*id);
    }
    if tgid != 0 {
        return unsafe { BLOCK_TGID.get(&tgid) }.copied();
    }
    None
}

/// Process of the socket that sent an egress packet, from its cookie.
#[inline(always)]
fn packet_tgid(ctx: &TcContext, egress: bool) -> u32 {
    if !egress || RULE_COUNT.get(0).copied().unwrap_or(0) == 0 {
        return 0;
    }
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    if cookie == 0 {
        return 0;
    }
    unsafe { SOCK_OWNER.get(&cookie) }.map_or(0, |o| o.tgid)
}

#[inline(always)]
fn count_drop(rule: u32) {
    if let Some(d) = RULE_DROPS.get_ptr_mut(rule) {
        unsafe { *d += 1 };
    }
}

struct Skb<'a>(&'a TcContext);

impl PacketSource for Skb<'_> {
    #[inline(always)]
    fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        self.0.load::<[u8; N]>(offset).ok()
    }
}

// Pass is TC_ACT_UNSPEC (TCX_NEXT), which lets the next program on the hook
// run. TC_ACT_OK would be TCX_PASS and would skip every tcx program attached
// after netmon. Blocked packets get TC_ACT_SHOT.

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    handle(&ctx, true)
}

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    handle(&ctx, false)
}

#[inline(always)]
fn handle(ctx: &TcContext, egress: bool) -> i32 {
    let skb = ctx.as_ptr() as *const __sk_buff;
    let ifindex = unsafe { (*skb).ifindex };
    // skb->protocol holds a big-endian u16.
    let ethertype = u16::from_be(ctx.skb.protocol() as u16);
    let l3 = unsafe { L3_OFFSET.get(&ifindex) }.copied().unwrap_or(14);

    let key = parse_packet(&Skb(ctx), l3 as usize, ethertype)
        .map(|pkt| FlowKey::from_packet(&pkt, ifindex, egress));
    let mut action = TC_ACT_UNSPEC;
    if let Some(key) = &key {
        count(ctx, key, egress);
        // Unparsed packets have no key and pass (fail-open).
        if ifindex != LOOPBACK_IFINDEX
            && let Some(rule) =
                verdict(key.family, &key.remote_addr, key.proto, key.remote_port, packet_tgid(ctx, egress))
        {
            count_drop(rule);
            action = TC_ACT_SHOT;
        }
    }

    let Some(cfg) = CAPTURE_CFG.get(0) else { return action };
    // Every loopback packet passes egress and then ingress. Capture it once,
    // on egress. The ingress side of the flow is the reversed key.
    let lo = ifindex == LOOPBACK_IFINDEX;
    if lo && !egress {
        return action;
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
    action
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

// Socket hooks on the root cgroup. They run in the context of the process
// that creates or uses the socket. They return 1 (allow), except connect and
// sendmsg to a blocked destination, which return 0: the call fails with
// EPERM.

const ALLOW: i32 = 1;
const DENY: i32 = 0;

/// Verdict for a connect/sendmsg destination. user_port holds the port in
/// network order in its low 16 bits; native-order bytes give the wire bytes.
#[inline(always)]
fn addr_verdict(ctx: &SockAddrContext, family: u8) -> i32 {
    let sa = ctx.sock_addr;
    let proto = unsafe { (*sa).protocol } as u8;
    let pb = unsafe { (*sa).user_port }.to_ne_bytes();
    let port = u16::from_be_bytes([pb[0], pb[1]]);
    let mut addr = [0u8; 16];
    // Each hook may read only its own family's address field.
    if family == 4 {
        addr[..4].copy_from_slice(&unsafe { (*sa).user_ip4 }.to_ne_bytes());
    } else {
        let ip6 = unsafe { (*sa).user_ip6 };
        let mut i = 0;
        while i < 4 {
            addr[i * 4..i * 4 + 4].copy_from_slice(&ip6[i].to_ne_bytes());
            i += 1;
        }
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    match verdict(family, &addr, proto, port, tgid) {
        Some(rule) => {
            count_drop(rule);
            DENY
        }
        None => ALLOW,
    }
}

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
    addr_verdict(&ctx, 4)
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    record_owner(ctx.as_ptr());
    addr_verdict(&ctx, 6)
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    record_owner(ctx.as_ptr());
    addr_verdict(&ctx, 4)
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    record_owner(ctx.as_ptr());
    addr_verdict(&ctx, 6)
}

// Process tracking for exe blocks. Both programs run in the context of the
// task that execs or forks, so the current tgid is the right process.

/// After exec: the process is blocked if its new exe is, and unblocked
/// otherwise. That also clears a stale entry when a pid is reused.
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    let Some(cfg) = TRACE_CFG.get(0) else { return 0 };
    if cfg.exec_filename == 0 {
        return 0;
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // __data_loc: low 16 bits offset of the string in the record.
    let Ok(loc) = (unsafe { ctx.read_at::<u32>(cfg.exec_filename as usize) }) else { return 0 };
    let mut path = [0u8; MAX_EXE_PATH];
    let src = unsafe { (ctx.as_ptr() as *const u8).add((loc & 0xffff) as usize) };
    if unsafe { bpf_probe_read_kernel_str_bytes(src, &mut path) }.is_err() {
        return 0;
    }
    match unsafe { BLOCK_EXE.get(&path) } {
        Some(id) => {
            let _ = BLOCK_TGID.insert(&tgid, id, 0);
        }
        None => {
            let _ = BLOCK_TGID.remove(&tgid);
        }
    }
    0
}

/// After fork: the child has its parent's block state. Clearing it for an
/// unblocked parent removes stale entries of a reused pid.
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    let Some(cfg) = TRACE_CFG.get(0) else { return 0 };
    if cfg.fork_child_pid == 0 {
        return 0;
    }
    let Ok(child) = (unsafe { ctx.read_at::<u32>(cfg.fork_child_pid as usize) }) else { return 0 };
    let parent = (bpf_get_current_pid_tgid() >> 32) as u32;
    match unsafe { BLOCK_TGID.get(&parent) } {
        Some(id) => {
            let id = *id;
            let _ = BLOCK_TGID.insert(&child, &id, 0);
        }
        None => {
            let _ = BLOCK_TGID.remove(&child);
        }
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
