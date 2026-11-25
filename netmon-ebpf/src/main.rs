#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_F_NO_PREALLOC, BPF_NOEXIST, TC_ACT_SHOT, TC_ACT_UNSPEC, __sk_buff, bpf_fib_lookup as FibParams},
    cty::c_void,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_fib_lookup, bpf_get_current_uid_gid, bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_loop,
        bpf_get_current_task, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_skb_load_bytes,
    },
    macros::{cgroup_sock, cgroup_sock_addr, classifier, map, tracepoint},
    maps::{Array, HashMap, LruHashMap, LruPerCpuHashMap, PerCpuArray, RingBuf},
    programs::{SockAddrContext, SockContext, TcContext, TracePointContext},
};
use netmon_common::{
    ACTION_ALLOW, ACTION_ASK, ACTION_DENY, CFG_LIMITS, Limit, take_tokens, CFG_SNI, FNV_OFFSET, MAX_SNI_LEN,
    MAX_SNI_NAMES, SNI_BELOW, SNI_SELF, sni_step, NAME_DNS_TCP, ANSWER_STICKY, SniWalk, sni_walk, ASK_RING_BYTES, AskEvent, DENY_RING_BYTES, DenyEvent, CAPTURE_FLOWS, CAPTURE_IFACE, CAPTURE_LEN, CAPTURE_RING_BYTES,
    CFG_ACTIVE, CFG_COUNT, CFG_DEFAULT, CFG_GEN, CFG_LEN, CaptureConfig, ConnKey, ConnState, DIR_IN,
    DIR_OUT, FlowKey, FlowStats, GuardKey, IPPROTO_TCP, IPPROTO_UDP, LOOPBACK_IFINDEX, ListenKey,
    ListenOwner, MAX_CAPTURE_FLOWS, MAX_CONNS, NAME_DATA, NAME_DNS, NAME_RING_BYTES, NAME_TLS, NAME_TLS_CONT, MAX_HELLO_PENDING, NameEvent, MAX_EXE_PATH, MAX_FLOWS, MAX_GUARD, MAX_IFACES,
    AddrKey, CLONE_THREAD, ExeInode, MAX_BLOCKED_ADDRS, MAX_LISTENERS, MAX_MARKED_TGIDS, MAX_RULES, MAX_SOCK_OWNERS, PacketEvent, PacketSource,
    RuleEntry, SockOwner, TraceCfg, fib_forwarded, is_dhcp, is_loopback, is_unparsed, keep_answer, parse_packet, rule_matches,
    unmap_v4_in_place,
};

/// Byte counters per flow and interface.
#[map]
static FLOWS: LruPerCpuHashMap<FlowKey, FlowStats> =
    LruPerCpuHashMap::with_max_entries(MAX_FLOWS, 0);

/// ifindex -> offset of the IP header. Userspace sets 0 for devices
/// without a link-layer header (tun, wireguard). Missing means 14 (Ethernet).
#[map]
static L3_OFFSET: HashMap<u32, u32> = HashMap::with_max_entries(MAX_IFACES, 0);

/// Bridges and veth/vlan devices (any value). Containers and VMs send
/// through them: a packet there is the host's only if it comes from a
/// host socket or goes to a host address. Forwarded packets are decided at
/// the interface where they leave the host.
#[map]
static TRANSIT_IFACES: HashMap<u32, u8> = HashMap::with_max_entries(MAX_IFACES, 0);

/// What to capture. Index 0 only. Mode CAPTURE_OFF costs one lookup.
#[map]
static CAPTURE_CFG: Array<CaptureConfig> = Array::with_max_entries(1, 0);

/// Flow keys to capture in CAPTURE_FLOWS mode (process or connection).
#[map]
static CAPTURE_KEYS: HashMap<FlowKey, u8> = HashMap::with_max_entries(MAX_CAPTURE_FLOWS, 0);

/// Captured packets for userspace.
#[map]
static PACKETS: RingBuf = RingBuf::with_byte_size(CAPTURE_RING_BYTES, 0);

/// DNS answers and TLS ClientHellos for hostnames. Always on; full means
/// the event is dropped and that name is missed.
#[map]
static NAMES: RingBuf = RingBuf::with_byte_size(NAME_RING_BYTES, 0);

/// Connections whose ClientHello did not fit its first segment: their next
/// egress data segment goes to NAMES too.
#[map]
static HELLO_PENDING: LruHashMap<FlowKey, u8> = LruHashMap::with_max_entries(MAX_HELLO_PENDING, 0);

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

// Rules. Verdict maps are never LRU: an evicted entry would silently change
// a verdict. Userspace keeps them; they end with the process (fail-open).

/// Ordered rule table, two halves of MAX_RULES. Userspace writes the
/// inactive half and then flips CFG_ACTIVE, so a packet never sees a
/// half-written table.
#[map]
static RULES: Array<RuleEntry> = Array::with_max_entries(2 * MAX_RULES, 0);

/// CFG_ACTIVE and the rule count of each half (CFG_COUNT + half).
#[map]
static RULE_CFG: Array<u32> = Array::with_max_entries(CFG_LEN, 0);

/// Remote endpoints that are never blocked (lockout guard).
#[map]
static GUARD: HashMap<GuardKey, u8> = HashMap::with_max_entries(MAX_GUARD, 0);

/// Addresses of blocked hostnames -> connections denied so far. User
/// space fills it from DNS answers and TLS names. Not LRU: a block must
/// never be evicted.
#[map]
static HOST_BLOCKS: HashMap<AddrKey, u64> = HashMap::with_max_entries(MAX_BLOCKED_ADDRS, 0);

/// Exe paths named by rules (NUL-padded) -> exe id.
#[map]
static EXE_IDS: HashMap<[u8; MAX_EXE_PATH], u32> = HashMap::with_max_entries(MAX_RULES, 0);

/// File of each exe that rules name -> exe id. Matches however the exe was
/// started: relative path, `..`, symlink, execveat.
#[map]
static EXE_INODES: HashMap<ExeInode, u32> = HashMap::with_max_entries(MAX_RULES, 0);

/// Processes (tgid) -> exe id, for processes running an exe named by a
/// rule. Set by the exec and fork tracepoints and by userspace for
/// processes that already run.
#[map]
static TGID_EXE: HashMap<u32, u32> = HashMap::with_max_entries(MAX_MARKED_TGIDS, 0);

/// Tracepoint field offsets from userspace. Index 0 only.
#[map]
static TRACE_CFG: Array<TraceCfg> = Array::with_max_entries(1, 0);

/// Blocked server names: sni_hash -> SNI_SELF | SNI_BELOW. Not
/// preallocated: block lists can hold two million names.
#[map]
static SNI_BLOCKS: HashMap<u64, u8> = HashMap::with_max_entries(MAX_SNI_NAMES, BPF_F_NO_PREALLOC);

/// Where the extension walk of a ClientHello goes on in the connection's
/// next segment: the first segment ended between two extensions before
/// the server name.
#[repr(C)]
#[derive(Clone, Copy)]
struct SniPending {
    /// Offset of the next extension header in the next segment's payload.
    skip: u32,
    /// Extension bytes left from there.
    left: u32,
}

#[map]
static SNI_PENDING: LruHashMap<FlowKey, SniPending> = LruHashMap::with_max_entries(MAX_HELLO_PENDING, 0);

/// The server name of the ClientHello being checked. Index 0 only.
#[map]
static SNI_BUF: PerCpuArray<[u8; 256]> = PerCpuArray::with_max_entries(1, 0);

/// Bandwidth limits by exe id. Never LRU, like the verdict maps.
#[map]
static LIMITS: HashMap<u32, Limit> = HashMap::with_max_entries(MAX_RULES, 0);

/// Packets and socket calls matched, per table slot (both halves).
#[map]
static RULE_HITS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2 * MAX_RULES, 0);

#[inline(always)]
fn cfg(i: u32) -> u32 {
    RULE_CFG.get(i).copied().unwrap_or(0)
}

/// Rule count of the live half, and the half (0 or 1).
#[inline(always)]
fn live_rules() -> (u32, u32) {
    let half = cfg(CFG_ACTIVE) & 1;
    (cfg(CFG_COUNT + half), half)
}

/// Is any rule, default deny or ask in force? If not, nothing is checked
/// and no connection state is kept.
#[inline(always)]
fn rules_active() -> bool {
    let (count, half) = live_rules();
    let d = cfg(CFG_DEFAULT + half);
    count != 0 || d == ACTION_DENY as u32 || d == ACTION_ASK as u32 || cfg(CFG_LIMITS) != 0 || cfg(CFG_SNI) != 0
}

/// State of the walk over the server name, from its last byte to the first.
#[repr(C)]
struct SniScan {
    len: u32,
    hit: u32,
    h: u64,
}

/// bpf_loop callback: one byte of the name, from the end. At a dot, the
/// hash so far is the parent domain to the right: blocked if a block
/// covers the names below it.
#[inline(never)]
extern "C" fn sni_byte(i: u64, ctx: *mut c_void) -> i64 {
    let s = unsafe { &mut *(ctx as *mut SniScan) };
    let i = i as u32;
    if i >= s.len {
        return 1;
    }
    let Some(buf) = SNI_BUF.get_ptr(0) else { return 1 };
    let idx = ((s.len - 1 - i) & 0xff) as usize;
    let c = unsafe { (*buf)[idx] };
    if c == b'.'
        && let Some(f) = unsafe { SNI_BLOCKS.get(&s.h) }
        && *f & SNI_BELOW != 0
    {
        s.hit = 1;
        return 1;
    }
    s.h = sni_step(s.h, c);
    0
}

/// Does the TLS ClientHello at `off` name a blocked server? The walk over
/// the extensions (`sni_walk`) goes on in the next segment if the first
/// one ends between two extensions before the name. A name that the
/// segment border cuts passes.
#[inline(never)]
fn sni_blocked(ctx: &TcContext, key: &FlowKey, off: u32) -> bool {
    let pending = unsafe { SNI_PENDING.get(key) }.map(|p| (p.skip, p.left));
    if pending.is_some() {
        let _ = SNI_PENDING.remove(key);
    }
    let (name, n) = match sni_walk(&Skb(ctx), off, ctx.len(), pending) {
        SniWalk::Name { off, len } => (off, len),
        SniWalk::Pending { skip, left } => {
            let _ = SNI_PENDING.insert(key, &SniPending { skip, left }, 0);
            return false;
        }
        SniWalk::None => return false,
    };
    let mut n = n;
    if n > MAX_SNI_LEN as u32 {
        n = MAX_SNI_LEN as u32;
    }
    // As in name_event: the verifier needs n proven to be in 1..=255.
    let n = unsafe { core::ptr::read_volatile(&n) };
    if n == 0 || n > MAX_SNI_LEN as u32 {
        return false;
    }
    let Some(buf) = SNI_BUF.get_ptr_mut(0) else { return false };
    let ret = unsafe { bpf_skb_load_bytes(ctx.as_ptr() as *const c_void, name, buf as *mut c_void, n) };
    if ret != 0 {
        return false;
    }
    // A final dot (`name.`) is the same name.
    let mut n = n;
    if unsafe { (*buf)[((n - 1) & 0xff) as usize] } == b'.' {
        n -= 1;
    }
    if n == 0 {
        return false;
    }
    let mut scan = SniScan { len: n, hit: 0, h: FNV_OFFSET };
    unsafe {
        bpf_loop(n, sni_byte as *mut c_void, &mut scan as *mut SniScan as *mut c_void, 0);
    }
    if scan.hit != 0 {
        return true;
    }
    unsafe { SNI_BLOCKS.get(&scan.h) }.is_some_and(|f| *f & SNI_SELF != 0)
}

/// Marks the connection of a blocked ClientHello as denied, so its later
/// packets drop too, and logs the denial once.
#[inline(never)]
fn sni_deny(key: &FlowKey, tgid: u32) {
    let mut c = ConnKey::default();
    conn_key(key, &mut c);
    let prev = unsafe { CONNS.get(&c) }.map_or(0, |s| s.action);
    // Sticky: a rule change later must not allow the rest of it.
    let st = ConnState { generation: cfg(CFG_GEN), dir: DIR_OUT, action: ACTION_DENY, exe_known: 1, answered: ANSWER_STICKY, tgid };
    let _ = CONNS.insert(&c, &st, 0);
    if prev != ACTION_DENY {
        deny_event(&c, tgid);
    }
}

/// Is this packet over the bandwidth limit of its process's exe? Egress
/// packets name their process by the socket (`tgid`), ingress packets by
/// the connection state. Takes the packet's bytes from the bucket.
#[inline(never)]
fn over_limit(key: &FlowKey, egress: bool, tgid: u32, len: u64) -> bool {
    if cfg(CFG_LIMITS) == 0 {
        return false;
    }
    let mut tgid = tgid;
    if tgid == 0 {
        let mut c = ConnKey::default();
        conn_key(key, &mut c);
        tgid = unsafe { CONNS.get(&c) }.map_or(0, |s| s.tgid);
    }
    if tgid == 0 {
        return false;
    }
    let Some(exe) = (unsafe { TGID_EXE.get(&tgid) }).copied() else { return false };
    let Some(l) = LIMITS.get_ptr_mut(&exe) else { return false };
    let now = unsafe { bpf_ktime_get_ns() };
    let l = unsafe { &mut *l };
    let b = if egress { &mut l.up } else { &mut l.down };
    !take_tokens(b, now, len)
}

/// Outbound connections waiting for the user's answer (ask mode).
#[map]
static ASKS: RingBuf = RingBuf::with_byte_size(ASK_RING_BYTES, 0);

/// Sends an ask event. False if the ring is full: the caller must then
/// not cache the ask, so the next packet (a retransmit) tries again.
#[inline(never)]
fn ask_event(c: &ConnKey, tgid: u32) -> bool {
    let Some(mut e) = ASKS.reserve::<AskEvent>(0) else { return false };
    let ev = e.as_mut_ptr();
    unsafe {
        (*ev).key = *c;
        (*ev).tgid = tgid;
        (*ev)._pad = 0;
    }
    e.submit(0);
    true
}

/// Outbound connections that were denied, for the connection log.
#[map]
static DENIES: RingBuf = RingBuf::with_byte_size(DENY_RING_BYTES, 0);

/// Sends a deny event. A full ring loses the event: the log misses it,
/// the verdict does not change.
#[inline(never)]
fn deny_event(c: &ConnKey, tgid: u32) {
    let Some(mut e) = DENIES.reserve::<DenyEvent>(0) else { return };
    let ev = e.as_mut_ptr();
    unsafe {
        (*ev).key = *c;
        (*ev).tgid = tgid;
        (*ev)._pad = 0;
        (*ev).comm = bpf_get_current_comm().unwrap_or([0; 16]);
    }
    e.submit(0);
}

/// Connection -> direction and cached verdict. LRU is fine here: an
/// evicted entry is decided again (an inbound reply may then count as a
/// new outbound connection).
#[map]
static CONNS: LruHashMap<ConnKey, ConnState> = LruHashMap::with_max_entries(MAX_CONNS, 0);

/// State of one rule table walk, on the caller's stack. Starts with the
/// guard key, so the address is stored once.
#[repr(C)]
struct Scan {
    guard: GuardKey,
    exe: u32,
    base: u32,
    count: u32,
    proto: u8,
    dir: u8,
    /// Action of the first matching rule, 0 if none matched.
    action: u8,
    _pad: u8,
}

/// bpf_loop callback: checks rule `i`. Returns 1 to stop the walk.
/// The verifier checks this body once, not once per rule, which keeps
/// the programs far below the 1M instruction limit.
#[inline(never)]
extern "C" fn scan_rule(i: u64, ctx: *mut c_void) -> i64 {
    let s = unsafe { &mut *(ctx as *mut Scan) };
    let i = i as u32;
    if i >= s.count {
        return 1;
    }
    let slot = s.base + i;
    let Some(r) = RULES.get(slot) else { return 1 };
    let g = &s.guard;
    if !rule_matches(r, g.family, &g.addr, s.proto, g.port, s.exe, s.dir) {
        return 0;
    }
    if let Some(h) = RULE_HITS.get_ptr_mut(slot) {
        unsafe { *h += 1 };
    }
    s.action = r.action;
    1
}

/// The action for connection `c` of process `tgid` (0: unknown) in
/// direction `dir`. Loopback, guarded endpoints, DHCP and TCP/UDP packets
/// without ports (later fragments) are allowed. Otherwise the first
/// matching rule decides and counts a hit; with no match TCP and UDP get
/// the default action and other protocols are allowed.
///
/// A separate BPF function: the bpf_loop callback frame adds to this small
/// one, not to the program frame. Programs, the functions they call and
/// the callback share a 512-byte stack. BPF functions take at most 5
/// arguments.
#[inline(never)]
fn decide(c: &ConnKey, tgid: u32, dir: u8) -> u8 {
    let (count, half) = live_rules();
    let tcp_udp = c.proto == IPPROTO_TCP || c.proto == IPPROTO_UDP;
    // Later fragments carry no ports: both are 0. A packet with only a
    // source port of 0 is checked like any other.
    let fragment = tcp_udp && c.remote_port == 0 && c.local_port == 0;
    if is_loopback(c.family, &c.remote_addr) || is_dhcp(c.proto, c.local_port, c.remote_port) || fragment {
        return ACTION_ALLOW;
    }
    if c.proto == IPPROTO_TCP && unsafe { GUARD.get(&GuardKey::local_tcp(c.local_port)) }.is_some() {
        return ACTION_ALLOW;
    }
    let mut scan = Scan {
        guard: GuardKey { addr: c.remote_addr, port: c.remote_port, family: c.family, proto: c.proto, dir: 0, _pad: [0; 3] },
        exe: 0,
        base: half * MAX_RULES,
        count: if count > MAX_RULES { MAX_RULES } else { count },
        proto: c.proto,
        dir,
        action: 0,
        _pad: 0,
    };
    // Guarded in both directions, or in this one.
    if unsafe { GUARD.get(&scan.guard) }.is_some() {
        return ACTION_ALLOW;
    }
    scan.guard.dir = dir;
    if unsafe { GUARD.get(&scan.guard) }.is_some() {
        return ACTION_ALLOW;
    }
    // A blocked hostname wins over every rule, like a UI block.
    if host_blocked(c) {
        return ACTION_DENY;
    }
    if scan.count == 0 {
        return default_action(c.family, c.proto, dir, half);
    }
    if tgid != 0 {
        scan.exe = unsafe { TGID_EXE.get(&tgid) }.copied().unwrap_or(0);
    }
    unsafe {
        bpf_loop(scan.count, scan_rule as *mut c_void, &mut scan as *mut Scan as *mut c_void, 0);
    }
    if scan.action == 0 { default_action(scan.guard.family, scan.proto, scan.dir, half) } else { scan.action }
}

/// Is the remote end an address of a blocked hostname? Counts the hit.
/// Its own BPF function: the key stays off the rule walk's stack.
#[inline(never)]
fn host_blocked(c: &ConnKey) -> bool {
    let k = AddrKey { addr: c.remote_addr, family: c.family, _pad: [0; 3] };
    match HOST_BLOCKS.get_ptr_mut(&k) {
        Some(hits) => {
            // Not atomic: a lost count on a race is fine.
            unsafe { *hits += 1 };
            true
        }
        None => false,
    }
}

/// Action when no rule matches: the configured default for TCP and UDP
/// (ask only outbound; unmatched inbound is denied), allow otherwise.
/// Computed after the rule walk so it takes no stack across bpf_loop.
#[inline(always)]
fn default_action(family: u8, proto: u8, dir: u8, half: u32) -> u8 {
    // An IPv6 packet whose upper header the parser did not reach could be
    // TCP or UDP: it gets their default, not a free pass.
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP && !is_unparsed(family, proto) {
        return ACTION_ALLOW;
    }
    let d = cfg(CFG_DEFAULT + half);
    if d == ACTION_DENY as u32 {
        ACTION_DENY
    } else if d == ACTION_ASK as u32 {
        if dir == DIR_OUT { ACTION_ASK } else { ACTION_DENY }
    } else {
        ACTION_ALLOW
    }
}

/// TC verdict for a packet of flow `key`. TCP and UDP use the connection
/// state: the first packet sets the direction (egress: out, ingress: in)
/// and the verdict, later packets reuse it until the rules change. An
/// `ask` verdict drops packets until userspace writes the answer into the
/// state; only the packet that decides sends an ask event.
#[inline(never)]
fn packet_denied(key: &FlowKey, egress: bool, tgid: u32) -> bool {
    if !rules_active() {
        return false;
    }
    let mut c = ConnKey::default();
    conn_key(key, &mut c);
    let mut dir = if egress { DIR_OUT } else { DIR_IN };
    if c.proto != IPPROTO_TCP && c.proto != IPPROTO_UDP {
        // No connection state and no question: an unparsed IPv6 packet in
        // ask mode is dropped.
        return decide(&c, tgid, dir) != ACTION_ALLOW;
    }
    let generation = cfg(CFG_GEN);
    let (mut prev_action, mut prev_answered) = (0u8, 0u8);
    let mut tgid = tgid;
    if let Some(st) = unsafe { CONNS.get(&c) } {
        // Decide again after a rule change, or when the process is known
        // now but was not then (exe rules could not match).
        if st.current(generation, tgid) {
            return st.action != ACTION_ALLOW;
        }
        dir = st.dir;
        prev_action = st.action;
        prev_answered = st.answered;
        // The owner map can have lost the socket (LRU): keep the process
        // the connection was decided for.
        if tgid == 0 {
            tgid = st.tgid;
        }
    }
    if tgid == 0 && dir == DIR_IN {
        tgid = listener_tgid(key);
    }
    let (action, answered) = keep_answer(decide(&c, tgid, dir), prev_action, prev_answered);
    // A lost ask event is not cached: the retransmit asks again.
    // Only the decision that turns a connection to deny is logged, not each
    // dropped packet.
    if action == ACTION_DENY && dir == DIR_OUT && prev_action != ACTION_DENY {
        deny_event(&c, tgid);
    }
    if action == ACTION_ASK && !ask_event(&c, tgid) {
        return true;
    }
    // Denied inbound packets are not remembered: a remote host that sends
    // many new flows must not push real connections out of the LRU map.
    if dir == DIR_IN && action == ACTION_DENY {
        return true;
    }
    let st = ConnState { generation, dir, action, exe_known: (tgid != 0) as u8, answered, tgid };
    let _ = CONNS.insert(&c, &st, 0);
    action != ACTION_ALLOW
}

/// ConnKey::from_flow in its own BPF function: unmapping the address takes
/// stack that would otherwise sit under the rule walk.
#[inline(never)]
fn conn_key(key: &FlowKey, out: &mut ConnKey) {
    *out = ConnKey::from_flow(key);
}

/// The process that bound the local end of an inbound flow (a server),
/// from the post_bind hooks: exact address first, then the wildcard.
#[inline(never)]
fn listener_tgid(key: &FlowKey) -> u32 {
    let mut lk = ListenKey { addr: key.local_addr, port: key.local_port, proto: key.proto, family: key.family };
    if let Some(o) = unsafe { LISTENERS.get(&lk) } {
        return o.owner.tgid;
    }
    lk.addr = [0; 16];
    unsafe { LISTENERS.get(&lk) }.map_or(0, |o| o.owner.tgid)
}

/// Verdict for connect/sendmsg. Usually a new outbound connection; a UDP
/// reply a server sends with sendto() belongs to an inbound one, found by
/// the socket's local port. `ask` allows the call: TC then drops the
/// packet and asks.
#[inline(never)]
fn sock_denied(c: &ConnKey, tgid: u32) -> bool {
    if !rules_active() {
        return false;
    }
    let mut dir = DIR_OUT;
    let (mut prev_action, mut prev_answered) = (0u8, 0u8);
    if c.local_port != 0
        && let Some(st) = unsafe { CONNS.get(c) }
    {
        if st.generation == cfg(CFG_GEN) && (st.answered != 0 || st.exe_known != 0) {
            return st.action == ACTION_DENY;
        }
        dir = st.dir;
        prev_action = st.action;
        prev_answered = st.answered;
    }
    let denied = keep_answer(decide(c, tgid, dir), prev_action, prev_answered).0 == ACTION_DENY;
    // Socket calls are not cached: a program that retries sends one event
    // per try. Userspace logs one line per destination and minute.
    if denied && dir == DIR_OUT {
        deny_event(c, tgid);
    }
    denied
}

/// Process of the socket that sent an egress packet, from its cookie.
#[inline(always)]
fn packet_tgid(ctx: &TcContext, egress: bool) -> u32 {
    if !egress || !rules_active() {
        return 0;
    }
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    if cookie == 0 {
        return 0;
    }
    unsafe { SOCK_OWNER.get(&cookie) }.map_or(0, |o| o.tgid)
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

/// Parses the packet into `out`, whose ifindex the caller sets. Returns
/// the payload offset (0: unknown), or -1 if the packet did not parse. A
/// separate BPF function for the same reason as count(): its stack stays
/// off the rule walk's. BPF functions take at most 5 arguments.
#[inline(never)]
fn parse_key(ctx: &TcContext, l3: u32, ethertype: u16, egress: bool, out: &mut FlowKey) -> i32 {
    match parse_packet(&Skb(ctx), l3 as usize, ethertype) {
        Some(pkt) => {
            *out = FlowKey::from_packet(&pkt, out.ifindex, egress);
            pkt.payload as i32
        }
        None => -1,
    }
}

/// Sends ClientHellos of egress TCP segments to userspace. A payload that
/// starts like a ClientHello (record type handshake 0x16, version 3.x,
/// handshake type 1) is sent; if its record is longer than the segment, the
/// connection's next data segment is sent too. Pure ACKs have no payload,
/// so the read fails and costs nothing more.
#[inline(never)]
fn tls_names(ctx: &TcContext, key: &FlowKey, off: u32) {
    let Ok(b) = ctx.load::<[u8; 6]>(off as usize) else { return };
    if b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01 {
        name_event(ctx, key, off, NAME_TLS);
        let record = 5 + u16::from_be_bytes([b[3], b[4]]) as u32;
        if record > ctx.len() - off {
            let _ = HELLO_PENDING.insert(key, &1, 0);
        }
    } else if unsafe { HELLO_PENDING.get(key) }.is_some() {
        name_event(ctx, key, off, NAME_TLS_CONT);
        let _ = HELLO_PENDING.remove(key);
    }
}

/// Sends the payload of a packet that may carry a hostname to userspace.
#[inline(never)]
fn name_event(ctx: &TcContext, key: &FlowKey, off: u32, kind: u8) {
    let len = ctx.len();
    if off == 0 || off >= len {
        return;
    }
    // The verifier needs the copy length proven to be in 1..=NAME_DATA.
    // The compiler knows n >= 1 from off < len and would drop a plain
    // check; the verifier does not know it. A volatile read hides the
    // value from the compiler, so the check stays in the program.
    let mut n = len - off;
    if n > NAME_DATA as u32 {
        n = NAME_DATA as u32;
    }
    let n = unsafe { core::ptr::read_volatile(&n) };
    if n == 0 || n > NAME_DATA as u32 {
        return;
    }
    let Some(mut entry) = NAMES.reserve::<NameEvent>(0) else { return };
    let ev = entry.as_mut_ptr();
    let ret = unsafe {
        bpf_skb_load_bytes(ctx.as_ptr() as *const c_void, off, (*ev).data.as_mut_ptr() as *mut c_void, n)
    };
    if ret != 0 {
        entry.discard(0);
        return;
    }
    unsafe {
        (*ev).key = *key;
        (*ev).len = n as u16;
        (*ev).kind = kind;
        (*ev)._pad = 0;
    }
    entry.submit(0);
}

/// A DNS answer to a query this host sent: the query left an outbound
/// connection state. A remote host that sends unasked answers must not
/// put a trusted name on its address. Loopback answers come from a local
/// resolver. Without rules no state is kept, and no question shows names.
#[inline(never)]
fn dns_solicited(key: &FlowKey) -> bool {
    if key.ifindex == LOOPBACK_IFINDEX || !rules_active() {
        return true;
    }
    let mut c = ConnKey::default();
    conn_key(key, &mut c);
    unsafe { CONNS.get(&c) }.is_some_and(|s| s.dir == DIR_OUT)
}

/// A packet that only passes through the host on a bridge or veth (a
/// container's connection to the internet, or to another container). It
/// is decided where it leaves the host, not here: on this side of the NAT
/// its direction is reversed.
#[inline(never)]
fn forwarded(ctx: &TcContext, key: &FlowKey, egress: bool) -> bool {
    if unsafe { TRANSIT_IFACES.get(&key.ifindex) }.is_none() {
        return false;
    }
    if egress {
        // Sent by a host socket, or forwarded (no socket).
        return unsafe { bpf_get_socket_cookie(ctx.as_ptr()) } == 0;
    }
    // On ingress the destination is the local side of the key.
    let mut p: FibParams = unsafe { core::mem::zeroed() };
    p.l4_protocol = key.proto;
    p.sport = key.remote_port.to_be();
    p.dport = key.local_port.to_be();
    p.ifindex = key.ifindex;
    if key.family == 4 {
        p.family = 2; // AF_INET
        p.__bindgen_anon_3.ipv4_src = u32::from_ne_bytes([key.remote_addr[0], key.remote_addr[1], key.remote_addr[2], key.remote_addr[3]]);
        p.__bindgen_anon_4.ipv4_dst = u32::from_ne_bytes([key.local_addr[0], key.local_addr[1], key.local_addr[2], key.local_addr[3]]);
    } else {
        p.family = 10; // AF_INET6
        let mut i = 0;
        while i < 4 {
            let r = &key.remote_addr[i * 4..i * 4 + 4];
            let l = &key.local_addr[i * 4..i * 4 + 4];
            unsafe {
                p.__bindgen_anon_3.ipv6_src[i] = u32::from_ne_bytes([r[0], r[1], r[2], r[3]]);
                p.__bindgen_anon_4.ipv6_dst[i] = u32::from_ne_bytes([l[0], l[1], l[2], l[3]]);
            }
            i += 1;
        }
    }
    let ret = unsafe { bpf_fib_lookup(ctx.as_ptr(), &mut p, size_of::<FibParams>() as i32, 0) };
    fib_forwarded(ret)
}

#[inline(always)]
fn handle(ctx: &TcContext, egress: bool) -> i32 {
    let skb = ctx.as_ptr() as *const __sk_buff;
    let ifindex = unsafe { (*skb).ifindex };
    // skb->protocol holds a big-endian u16.
    let ethertype = u16::from_be(ctx.skb.protocol() as u16);
    let l3 = unsafe { L3_OFFSET.get(&ifindex) }.copied().unwrap_or(14);

    let mut parsed = FlowKey { ifindex, ..FlowKey::default() };
    let payload = parse_key(ctx, l3, ethertype, egress, &mut parsed);
    let key = (payload >= 0).then_some(parsed);
    let mut action = TC_ACT_UNSPEC;
    if let Some(key) = &key {
        count(ctx, key, egress);
        if egress && key.proto == IPPROTO_TCP && payload > 0 {
            tls_names(ctx, key, payload as u32);
        }
        // Unparsed packets have no key and pass (fail-open).
        let local = ifindex != LOOPBACK_IFINDEX && !forwarded(ctx, key, egress);
        let tgid = if local { packet_tgid(ctx, egress) } else { 0 };
        let denied = local && packet_denied(key, egress, tgid);
        if denied || (local && over_limit(key, egress, tgid, ctx.len() as u64)) {
            action = TC_ACT_SHOT;
        } else if local
            && egress
            && key.proto == IPPROTO_TCP
            && payload > 0
            && cfg(CFG_SNI) != 0
            && sni_blocked(ctx, key, payload as u32)
        {
            sni_deny(key, tgid);
            action = TC_ACT_SHOT;
        }
        // DNS answers: from port 53, on every interface (lo carries the
        // answers of a local stub resolver). Only answers to a query of
        // this host: the names show in questions.
        if !egress && !denied && key.remote_port == 53 && payload > 0 && dns_solicited(key) {
            if key.proto == IPPROTO_UDP {
                name_event(ctx, key, payload as u32, NAME_DNS);
            } else if key.proto == IPPROTO_TCP {
                name_event(ctx, key, payload as u32, NAME_DNS_TCP);
            }
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

// count() and capture() are separate BPF functions, not inlined: their
// stack then does not add to the rule walk's (bpf_loop callback frame plus
// the program frame must stay within 512 bytes).
#[inline(never)]
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
#[inline(never)]
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
// sendmsg to a denied destination, which return 0: the call fails with
// EPERM.

const ALLOW: i32 = 1;
const DENY: i32 = 0;

/// Verdict for a connect/sendmsg destination. user_port holds the port in
/// network order in its low 16 bits; native-order bytes give the wire bytes.
#[inline(always)]
fn addr_verdict(ctx: &SockAddrContext, family: u8) -> i32 {
    let sa = ctx.sock_addr;
    let pb = unsafe { (*sa).user_port }.to_ne_bytes();
    let mut c = ConnKey {
        proto: unsafe { (*sa).protocol } as u8,
        remote_port: u16::from_be_bytes([pb[0], pb[1]]),
        family,
        ..ConnKey::default()
    };
    // Each hook may read only its own family's address field.
    if family == 4 {
        c.remote_addr[..4].copy_from_slice(&unsafe { (*sa).user_ip4 }.to_ne_bytes());
    } else {
        let ip6 = unsafe { (*sa).user_ip6 };
        let mut i = 0;
        while i < 4 {
            c.remote_addr[i * 4..i * 4 + 4].copy_from_slice(&ip6[i].to_ne_bytes());
            i += 1;
        }
    }
    unmap_v4_in_place(&mut c.family, &mut c.remote_addr);
    // Local port in host order; 0 until the socket is bound.
    let sk = unsafe { (*sa).__bindgen_anon_1.sk };
    if !sk.is_null() {
        c.local_port = unsafe { (*sk).src_port } as u16;
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if sock_denied(&c, tgid) { DENY } else { ALLOW }
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

// Process tracking for exe rules. Both programs run in the context of the
// task that execs or forks, so the current tgid is the right process.

/// After exec: the process gets the exe id of its new exe if a rule names
/// it, else its entry is removed. That also clears a stale entry when a pid
/// is reused.
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    let Some(cfg) = TRACE_CFG.get(0) else { return 0 };
    if cfg.exec_filename == 0 {
        return 0;
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let id = exe_by_inode(cfg);
    if id != 0 {
        let _ = TGID_EXE.insert(&tgid, &id, 0);
        return 0;
    }
    // __data_loc: low 16 bits offset of the string in the record.
    let Ok(loc) = (unsafe { ctx.read_at::<u32>(cfg.exec_filename as usize) }) else { return 0 };
    let mut path = [0u8; MAX_EXE_PATH];
    let src = unsafe { (ctx.as_ptr() as *const u8).add((loc & 0xffff) as usize) };
    if unsafe { bpf_probe_read_kernel_str_bytes(src, &mut path) }.is_err() {
        return 0;
    }
    match unsafe { EXE_IDS.get(&path) } {
        Some(id) => {
            let _ = TGID_EXE.insert(&tgid, id, 0);
        }
        None => {
            let _ = TGID_EXE.remove(&tgid);
        }
    }
    0
}

/// Exe id of the file the current task now runs: current->mm->exe_file,
/// its inode and the device of its file system. The offsets come from BTF
/// (TraceCfg). The exec tracepoint fires after the new exe_file is set.
/// 0 if none. A BPF function returns one register: no Option here.
#[inline(never)]
fn exe_by_inode(cfg: &TraceCfg) -> u32 {
    exe_by_inode_inner(cfg).unwrap_or(0)
}

#[inline(always)]
fn exe_by_inode_inner(cfg: &TraceCfg) -> Option<u32> {
    if cfg.inode_ok == 0 {
        return None;
    }
    unsafe {
        let task = bpf_get_current_task() as *const u8;
        let mm: *const u8 = bpf_probe_read_kernel(task.add(cfg.task_mm as usize) as *const *const u8).ok()?;
        if mm.is_null() {
            return None;
        }
        let file: *const u8 = bpf_probe_read_kernel(mm.add(cfg.mm_exe_file as usize) as *const *const u8).ok()?;
        if file.is_null() {
            return None;
        }
        let inode: *const u8 = bpf_probe_read_kernel(file.add(cfg.file_inode as usize) as *const *const u8).ok()?;
        if inode.is_null() {
            return None;
        }
        let ino: u64 = bpf_probe_read_kernel(inode.add(cfg.inode_ino as usize) as *const u64).ok()?;
        let sb: *const u8 = bpf_probe_read_kernel(inode.add(cfg.inode_sb as usize) as *const *const u8).ok()?;
        if sb.is_null() {
            return None;
        }
        let dev: u32 = bpf_probe_read_kernel(sb.add(cfg.sb_dev as usize) as *const u32).ok()?;
        EXE_INODES.get(&ExeInode { dev, _pad: 0, ino }).copied()
    }
}

/// After fork: the new process gets its parent's exe id. Clearing it for
/// an unmarked parent removes stale entries of a reused pid. Threads are
/// skipped: rules look up processes (tgids), and thread ids would fill the
/// map.
#[tracepoint]
pub fn task_newtask(ctx: TracePointContext) -> u32 {
    let Some(cfg) = TRACE_CFG.get(0) else { return 0 };
    if cfg.newtask_pid == 0 {
        return 0;
    }
    let Ok(flags) = (unsafe { ctx.read_at::<u32>(cfg.newtask_flags as usize) }) else { return 0 };
    if flags & CLONE_THREAD != 0 {
        return 0;
    }
    let Ok(child) = (unsafe { ctx.read_at::<u32>(cfg.newtask_pid as usize) }) else { return 0 };
    let parent = (bpf_get_current_pid_tgid() >> 32) as u32;
    match unsafe { TGID_EXE.get(&parent) } {
        Some(id) => {
            let id = *id;
            let _ = TGID_EXE.insert(&child, &id, 0);
        }
        None => {
            let _ = TGID_EXE.remove(&child);
        }
    }
    0
}

/// When a process ends (its main thread exits), its mark goes.
#[tracepoint]
pub fn sched_process_exit(_ctx: TracePointContext) -> u32 {
    let id = bpf_get_current_pid_tgid();
    let (tgid, tid) = ((id >> 32) as u32, id as u32);
    if tgid == tid {
        let _ = TGID_EXE.remove(&tgid);
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
