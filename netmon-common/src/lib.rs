//! Types shared by the eBPF programs and the userspace loader, plus the
//! packet header parser. The parser reads through [`PacketSource`] so the
//! same code runs in the kernel (via `bpf_skb_load_bytes`) and in host tests.
#![no_std]

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Max flows kept in the kernel map. The map is LRU, so old flows drop out.
pub const MAX_FLOWS: u32 = 65_536;
/// Max interfaces with an explicit L3 offset.
pub const MAX_IFACES: u32 = 1_024;

/// The loopback device always has ifindex 1 on Linux.
pub const LOOPBACK_IFINDEX: u32 = 1;

/// One direction-independent flow as seen on one interface.
/// IPv4 addresses use the first 4 bytes; the rest stays zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowKey {
    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],
    pub ifindex: u32,
    pub local_port: u16,
    pub remote_port: u16,
    pub proto: u8,
    /// 4 or 6.
    pub family: u8,
    pub _pad: [u8; 2],
}

/// Byte and packet counters for one flow. Values are per CPU in the kernel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_pkts: u64,
    pub rx_pkts: u64,
    /// Socket cookie of the local socket, set by egress packets. 0 when
    /// unknown (only ingress so far, or forwarded traffic).
    pub cookie: u64,
}

/// Entries in the socket owner map.
pub const MAX_SOCK_OWNERS: u32 = 16_384;
/// Rules in the ordered rule table. The kernel walks the table for each
/// packet and socket call, so this stays small.
pub const MAX_RULES: u32 = 256;
/// Lockout guard entries.
pub const MAX_GUARD: u32 = 64;

/// Exe paths in the exe id map are NUL-padded to this length.
pub const MAX_EXE_PATH: usize = 256;
/// Processes (tgids) marked with the exe id of a rule.
pub const MAX_MARKED_TGIDS: u32 = 8_192;

// Rule fields: a rule matches when every field in its mask matches.
pub const RULE_NET: u8 = 1;
pub const RULE_PROTO: u8 = 2;
pub const RULE_PORT: u8 = 4;
pub const RULE_EXE: u8 = 8;
pub const RULE_DIR: u8 = 16;

pub const ACTION_ALLOW: u8 = 1;
pub const ACTION_DENY: u8 = 2;
/// Default action only: drop the first packet of an outbound connection
/// and ask the user; the answer is written into the connection state.
pub const ACTION_ASK: u8 = 3;

/// Size of the ring buffer for ask events.
pub const ASK_RING_BYTES: u32 = 256 * 1024;

/// An outbound connection that no rule decides, in ask mode.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AskEvent {
    pub key: ConnKey,
    /// Process that sent the packet, 0 if unknown.
    pub tgid: u32,
    pub _pad: u32,
}

/// This host opened the connection (or sends the datagram).
pub const DIR_OUT: u8 = 1;
/// The remote host opened the connection.
pub const DIR_IN: u8 = 2;

// Indexes in the RULE_CFG array. Separate u32 entries, so each update is
// one atomic write.
/// Which table half is live: 0 or 1.
pub const CFG_ACTIVE: u32 = 0;
/// Rule count of half 0; half 1 follows.
pub const CFG_COUNT: u32 = 1;
/// Action for TCP and UDP traffic no rule matches. 0 means allow.
pub const CFG_DEFAULT: u32 = 3;
/// Bumped on every table rewrite: cached connection verdicts of an older
/// generation are decided again.
pub const CFG_GEN: u32 = 4;
pub const CFG_LEN: u32 = 5;

/// Connections whose direction and verdict the kernel remembers.
pub const MAX_CONNS: u32 = 65_536;

/// A connection as the firewall sees it: the remote end, the local port
/// and the protocol. No local address and no interface, so the socket
/// hooks (which know neither for sure) and TC agree on the key.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct ConnKey {
    /// Remote address, IPv4-mapped addresses as IPv4.
    pub remote_addr: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
    pub family: u8,
    pub proto: u8,
    pub _pad: [u8; 2],
}

impl ConnKey {
    #[inline(always)]
    pub fn from_flow(k: &FlowKey) -> ConnKey {
        let mut c = ConnKey {
            remote_addr: k.remote_addr,
            local_port: k.local_port,
            remote_port: k.remote_port,
            family: k.family,
            proto: k.proto,
            _pad: [0; 2],
        };
        unmap_v4_in_place(&mut c.family, &mut c.remote_addr);
        c
    }
}

/// What the kernel remembers about a connection.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct ConnState {
    /// CFG_GEN when the verdict was made.
    pub generation: u32,
    /// DIR_OUT or DIR_IN: the side that sent the first packet.
    pub dir: u8,
    /// ACTION_ALLOW or ACTION_DENY.
    pub action: u8,
    /// 1 if the process was known when deciding, so exe rules could match.
    pub exe_known: u8,
    /// 1 if the user answered for this connection (ask mode, "once"): the
    /// verdict then stays through rule changes.
    pub answered: u8,
}

/// DHCP and DHCPv6 (client and server ports). Never blocked, so a host
/// with default deny keeps its address.
#[inline(always)]
/// DHCP and DHCPv6 of this host as a client: local 68 with server 67,
/// local 546 with server 547. Both ports must match: a remote host that
/// only picks source port 67 reaches nothing but the DHCP client port.
pub fn is_dhcp(proto: u8, local_port: u16, remote_port: u16) -> bool {
    proto == IPPROTO_UDP && ((local_port == 68 && remote_port == 67) || (local_port == 546 && remote_port == 547))
}

/// IPv6 extension header types the parser follows. A packet whose
/// protocol is still one of these after the walk has an upper header the
/// parser did not reach.
#[inline(always)]
pub fn is_unparsed(family: u8, proto: u8) -> bool {
    family == 6 && matches!(proto, 0 | 43 | 44 | 51 | 60)
}

/// One rule of the ordered rule table.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleEntry {
    /// Remote network, IPv4 in the first 4 bytes.
    pub addr: [u8; 16],
    /// Exe id (from the exe id map), never 0 when RULE_EXE is set.
    pub exe: u32,
    /// Remote port range, inclusive. port_lo is at least 1.
    pub port_lo: u16,
    pub port_hi: u16,
    /// RULE_* bits.
    pub fields: u8,
    /// ACTION_ALLOW or ACTION_DENY.
    pub action: u8,
    pub family: u8,
    pub prefix: u8,
    pub proto: u8,
    /// DIR_OUT or DIR_IN.
    pub dir: u8,
    pub _pad: [u8; 2],
}

/// Does `rule` match traffic to remote `addr`:`port` by a process with exe
/// id `exe` (0: unknown) in direction `dir`? `addr` must be normalized
/// (see `unmap_v4`). Port 0 (unknown, later fragments) never matches a
/// port rule; exe 0 never matches an exe rule.
#[inline(always)]
pub fn rule_matches(r: &RuleEntry, family: u8, addr: &[u8; 16], proto: u8, port: u16, exe: u32, dir: u8) -> bool {
    if r.fields & RULE_NET != 0 && (r.family != family || !in_prefix(addr, &r.addr, r.prefix)) {
        return false;
    }
    if r.fields & RULE_PROTO != 0 && r.proto != proto {
        return false;
    }
    if r.fields & RULE_PORT != 0 && (port < r.port_lo || port > r.port_hi) {
        return false;
    }
    if r.fields & RULE_EXE != 0 && (exe == 0 || exe != r.exe) {
        return false;
    }
    if r.fields & RULE_DIR != 0 && r.dir != dir {
        return false;
    }
    true
}

/// Are the first `prefix` bits of `a` and `net` equal? Unrolled over four
/// 32-bit words, so the verifier sees no loop.
#[inline(always)]
pub fn in_prefix(a: &[u8; 16], net: &[u8; 16], prefix: u8) -> bool {
    word_in_prefix(a, net, 0, prefix)
        && word_in_prefix(a, net, 1, prefix)
        && word_in_prefix(a, net, 2, prefix)
        && word_in_prefix(a, net, 3, prefix)
}

#[inline(always)]
fn word_in_prefix(a: &[u8; 16], net: &[u8; 16], i: usize, prefix: u8) -> bool {
    let start = (i * 32) as u8;
    if prefix <= start {
        return true;
    }
    let left = prefix - start;
    let mask = if left >= 32 { u32::MAX } else { u32::MAX << (32 - left) };
    let j = i * 4;
    let x = u32::from_be_bytes([a[j], a[j + 1], a[j + 2], a[j + 3]]);
    let y = u32::from_be_bytes([net[j], net[j + 1], net[j + 2], net[j + 3]]);
    (x ^ y) & mask == 0
}

/// unmap_v4 without copies, for the eBPF stack.
#[inline(always)]
pub fn unmap_v4_in_place(family: &mut u8, addr: &mut [u8; 16]) {
    let (f, a) = unmap_v4(*family, addr);
    if f != *family {
        *family = f;
        addr[0] = a[0];
        addr[1] = a[1];
        addr[2] = a[2];
        addr[3] = a[3];
        let mut i = 4;
        while i < 16 {
            addr[i] = 0;
            i += 1;
        }
    }
}

/// Turns an IPv4-mapped IPv6 address (::ffff:a.b.c.d, used by dual-stack
/// sockets) into IPv4, so IPv4 rules match it.
#[inline(always)]
pub fn unmap_v4(family: u8, addr: &[u8; 16]) -> (u8, [u8; 16]) {
    if family == 6
        && addr[0] == 0
        && addr[1] == 0
        && addr[2] == 0
        && addr[3] == 0
        && addr[4] == 0
        && addr[5] == 0
        && addr[6] == 0
        && addr[7] == 0
        && addr[8] == 0
        && addr[9] == 0
        && addr[10] == 0xff
        && addr[11] == 0xff
    {
        let mut v4 = [0u8; 16];
        v4[0] = addr[12];
        v4[1] = addr[13];
        v4[2] = addr[14];
        v4[3] = addr[15];
        return (4, v4);
    }
    (family, *addr)
}

/// Field offsets in the sched tracepoint records, read by userspace from
/// tracefs. 0 means unknown: the tracepoint program then does nothing.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TraceCfg {
    /// sched_process_exec: offset of the `__data_loc char[] filename` word.
    pub exec_filename: u32,
    /// sched_process_fork: offset of `pid_t child_pid`.
    pub fork_child_pid: u32,
}

/// A remote endpoint that is never blocked (SSH session, DNS resolver),
/// or, with family 0, a local TCP port that is never blocked (sshd).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct GuardKey {
    pub addr: [u8; 16],
    pub port: u16,
    pub family: u8,
    pub _pad: u8,
}

impl GuardKey {
    /// The key for a guarded local TCP port.
    #[inline(always)]
    pub fn local_tcp(port: u16) -> Self {
        GuardKey { addr: [0; 16], port, family: 0, _pad: IPPROTO_TCP }
    }
}

/// True for 127.0.0.0/8, ::1 and IPv4-mapped 127.x. Loopback is never
/// blocked.
#[inline(always)]
pub fn is_loopback(family: u8, addr: &[u8; 16]) -> bool {
    if family == 4 {
        return addr[0] == 127;
    }
    let mut i = 0;
    let mut zero_head = true;
    while i < 10 {
        if addr[i] != 0 {
            zero_head = false;
        }
        i += 1;
    }
    if !zero_head {
        return false;
    }
    if addr[10] == 0xff && addr[11] == 0xff {
        return addr[12] == 127;
    }
    addr[10] == 0 && addr[11] == 0 && addr[12] == 0 && addr[13] == 0 && addr[14] == 0 && addr[15] == 1
}

/// Entries in the bound socket (listener) map.
pub const MAX_LISTENERS: u32 = 4_096;

/// A bound local address: what `bind()` gave a socket. Wildcard binds have
/// an all-zero address.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ListenKey {
    pub addr: [u8; 16],
    pub port: u16,
    pub proto: u8,
    pub family: u8,
}

/// Owner of a bound socket. `cookie` lets the release hook remove only
/// its own entry when several sockets share a port (SO_REUSEPORT).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListenOwner {
    pub owner: SockOwner,
    pub cookie: u64,
}

/// Length of a task name (`comm`), with the trailing NUL.
pub const COMM_LEN: usize = 16;

/// The process that created or last used a socket, from the cgroup hooks.
/// Keyed by socket cookie, which the kernel never reuses until reboot.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockOwner {
    pub tgid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    pub comm: [u8; COMM_LEN],
}

/// Kinds of name events.
pub const NAME_DNS: u8 = 1;
pub const NAME_TLS: u8 = 2;
/// The next segment of a ClientHello longer than its first segment.
pub const NAME_TLS_CONT: u8 = 3;
/// Payload bytes kept per name event. Egress packets are often GSO
/// super-packets: a ClientHello with post-quantum key shares (~1.8 KB) is
/// then one packet here.
pub const NAME_DATA: usize = 4096;
/// Size of the always-on name event ring buffer.
pub const NAME_RING_BYTES: u32 = 4 * 1024 * 1024;
/// Connections whose ClientHello continues in the next segment.
pub const MAX_HELLO_PENDING: u32 = 1024;

/// A packet that may carry a hostname: a DNS answer (ingress from port 53)
/// or a TLS ClientHello (egress). Only the L4 payload is kept.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NameEvent {
    pub key: FlowKey,
    /// Bytes valid in `data`.
    pub len: u16,
    /// NAME_DNS or NAME_TLS.
    pub kind: u8,
    pub _pad: u8,
    pub data: [u8; NAME_DATA],
}

/// Bytes copied per captured packet. Longer packets (and GSO super-packets)
/// are cut; `PacketEvent::len` keeps the original length.
pub const CAPTURE_LEN: usize = 1500;
/// Ring buffer size for captured packets. Must be a power of two pages.
pub const CAPTURE_RING_BYTES: u32 = 8 * 1024 * 1024;
/// Max flows in a process or connection capture.
pub const MAX_CAPTURE_FLOWS: u32 = 4_096;

pub const CAPTURE_OFF: u32 = 0;
/// Capture every packet on `CaptureConfig::ifindex`.
pub const CAPTURE_IFACE: u32 = 1;
/// Capture packets whose flow key is in the CAPTURE_FLOWS map.
pub const CAPTURE_FLOWS: u32 = 2;

/// Single-entry array map set by userspace to start and stop a capture.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureConfig {
    pub mode: u32,
    pub ifindex: u32,
}

/// One captured packet, sent through the ring buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketEvent {
    /// CLOCK_MONOTONIC nanoseconds (bpf_ktime_get_ns).
    pub ts_ns: u64,
    pub ifindex: u32,
    /// Original packet length in bytes.
    pub len: u32,
    /// Bytes valid in `data`.
    pub cap_len: u32,
    /// Host-order L3 protocol (ETH_P_IP, ETH_P_IPV6, ...).
    pub ethertype: u16,
    pub egress: u8,
    /// 1 if `data` starts with an Ethernet header, 0 if with the IP header.
    pub has_l2: u8,
    pub data: [u8; CAPTURE_LEN],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for CaptureConfig {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowStats {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SockOwner {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ListenKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleEntry {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TraceCfg {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for GuardKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ListenOwner {}

/// Network and transport header fields of one packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    pub family: u8,
    pub proto: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    /// Offset of the TCP/UDP payload from the start of the data. 0 when
    /// unknown (no ports, other protocols, short header).
    pub payload: u16,
}

/// Reads fixed-size byte arrays at an offset into a packet.
pub trait PacketSource {
    fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]>;
}

impl PacketSource for &[u8] {
    fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        let end = offset.checked_add(N)?;
        let s = self.get(offset..end)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Some(out)
    }
}

/// Walks IPv6 extension headers from `next` at `off`. Returns the upper
/// protocol, its offset, and false for a non-first fragment.
#[inline(always)]
fn skip_ipv6_ext<S: PacketSource>(s: &S, mut next: u8, mut off: usize) -> (u8, usize, bool) {
    let mut first = true;
    for _ in 0..MAX_IPV6_EXT {
        let len = match next {
            // Hop-by-hop, routing, destination options: (len + 1) * 8.
            0 | 43 | 60 => match s.read::<2>(off) {
                Some(e) => {
                    next = e[0];
                    (e[1] as usize + 1) * 8
                }
                None => break,
            },
            // Fragment: 8 bytes. Offset != 0 means no transport header.
            44 => match s.read::<4>(off) {
                Some(e) => {
                    next = e[0];
                    if u16::from_be_bytes([e[2], e[3]]) & 0xfff8 != 0 {
                        first = false;
                    }
                    8
                }
                None => break,
            },
            // Authentication header: (len + 2) * 4.
            51 => match s.read::<2>(off) {
                Some(e) => {
                    next = e[0];
                    (e[1] as usize + 2) * 4
                }
                None => break,
            },
            _ => break,
        };
        off += len;
    }
    (next, off, first)
}

/// 802.1Q and 802.1ad (QinQ) VLAN tag protocol ids.
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_8021AD: u16 = 0x88A8;
/// VLAN tags followed in packet data (QinQ has 2).
pub const MAX_VLAN_TAGS: usize = 2;
/// IPv6 extension headers followed before giving up.
pub const MAX_IPV6_EXT: usize = 6;

/// Parses the IP header at `l3_offset` and, for TCP and UDP, the ports.
/// `ethertype` is the host-order L3 protocol (`ETH_P_IP`, `ETH_P_IPV6`, or
/// a VLAN tag protocol when the NIC did not strip the tag). Other protocols
/// return `None`.
///
/// Up to MAX_VLAN_TAGS tags and MAX_IPV6_EXT IPv6 extension headers are
/// skipped. Non-first fragments carry no ports. When a header cannot be
/// read, the packet is returned with what is known (fail-open): `proto` is
/// then the last header type and the ports are 0.
#[inline(always)]
pub fn parse_packet<S: PacketSource>(s: &S, l3_offset: usize, ethertype: u16) -> Option<Packet> {
    let mut l3_offset = l3_offset;
    let mut ethertype = ethertype;
    // Tags are in the data only on devices with a link-layer header, where
    // l3_offset points at the TCI after the tag protocol id.
    if l3_offset != 0 {
        for _ in 0..MAX_VLAN_TAGS {
            if ethertype != ETH_P_8021Q && ethertype != ETH_P_8021AD {
                break;
            }
            let t: [u8; 4] = s.read(l3_offset)?;
            ethertype = u16::from_be_bytes([t[2], t[3]]);
            l3_offset += 4;
        }
    }
    let mut p = Packet {
        family: 0,
        proto: 0,
        src: [0; 16],
        dst: [0; 16],
        sport: 0,
        dport: 0,
        payload: 0,
    };
    let l4_offset;
    let has_ports;
    match ethertype {
        ETH_P_IP => {
            let h: [u8; 20] = s.read(l3_offset)?;
            if h[0] >> 4 != 4 {
                return None;
            }
            let ihl = ((h[0] & 0x0f) as usize) * 4;
            if ihl < 20 {
                return None;
            }
            p.family = 4;
            p.proto = h[9];
            p.src[..4].copy_from_slice(&h[12..16]);
            p.dst[..4].copy_from_slice(&h[16..20]);
            let frag_offset = u16::from_be_bytes([h[6], h[7]]) & 0x1fff;
            l4_offset = l3_offset + ihl;
            has_ports = frag_offset == 0;
        }
        ETH_P_IPV6 => {
            let h: [u8; 40] = s.read(l3_offset)?;
            if h[0] >> 4 != 6 {
                return None;
            }
            p.family = 6;
            p.src.copy_from_slice(&h[8..24]);
            p.dst.copy_from_slice(&h[24..40]);
            let (proto, off, first) = skip_ipv6_ext(s, h[6], l3_offset + 40);
            p.proto = proto;
            l4_offset = off;
            has_ports = first;
        }
        _ => return None,
    }
    if has_ports && (p.proto == IPPROTO_TCP || p.proto == IPPROTO_UDP)
        && let Some(ports) = s.read::<4>(l4_offset) {
            p.sport = u16::from_be_bytes([ports[0], ports[1]]);
            p.dport = u16::from_be_bytes([ports[2], ports[3]]);
            if p.proto == IPPROTO_UDP {
                p.payload = (l4_offset + 8) as u16;
            } else if let Some([b]) = s.read::<1>(l4_offset + 12) {
                // TCP data offset: header length in 32-bit words.
                let doff = ((b >> 4) as usize) * 4;
                if doff >= 20 {
                    p.payload = (l4_offset + doff) as u16;
                }
            }
        }
    Some(p)
}

impl FlowKey {
    /// On egress the source is local. On ingress the destination is local.
    #[inline(always)]
    pub fn from_packet(p: &Packet, ifindex: u32, egress: bool) -> Self {
        let (local_addr, remote_addr, local_port, remote_port) = if egress {
            (p.src, p.dst, p.sport, p.dport)
        } else {
            (p.dst, p.src, p.dport, p.sport)
        };
        FlowKey {
            local_addr,
            remote_addr,
            ifindex,
            local_port,
            remote_port,
            proto: p.proto,
            family: p.family,
            _pad: [0; 2],
        }
    }

    /// The same flow seen from the other end (local and remote swapped).
    #[inline(always)]
    pub fn reversed(&self) -> Self {
        FlowKey {
            local_addr: self.remote_addr,
            remote_addr: self.local_addr,
            local_port: self.remote_port,
            remote_port: self.local_port,
            ..*self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: [u8; 4]) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&a);
        b
    }

    #[test]
    fn prefixes() {
        let net = v4([10, 1, 0, 0]);
        assert!(in_prefix(&v4([10, 1, 200, 3]), &net, 16));
        assert!(!in_prefix(&v4([10, 2, 0, 0]), &net, 16));
        assert!(in_prefix(&v4([99, 9, 9, 9]), &net, 0), "/0 matches all");
        assert!(in_prefix(&v4([10, 1, 0, 0]), &net, 32));
        assert!(!in_prefix(&v4([10, 1, 0, 1]), &net, 32));
        // 10.0.0.0/7 covers 10.x and 11.x, not 12.x.
        assert!(in_prefix(&v4([11, 0, 0, 0]), &v4([10, 0, 0, 0]), 7));
        assert!(!in_prefix(&v4([12, 0, 0, 0]), &v4([10, 0, 0, 0]), 7));
        let mut a = [0u8; 16];
        a[0] = 0x20;
        a[1] = 0x01;
        let mut b = a;
        b[15] = 1;
        assert!(in_prefix(&b, &a, 64));
        assert!(in_prefix(&b, &a, 127));
        assert!(!in_prefix(&b, &a, 128));
    }

    #[test]
    fn rule_fields() {
        let any = RuleEntry { action: ACTION_DENY, ..Default::default() };
        let dst = v4([1, 1, 1, 1]);
        assert!(rule_matches(&any, 4, &dst, IPPROTO_TCP, 443, 0, DIR_OUT), "no fields: matches all");
        let r = RuleEntry {
            fields: RULE_NET | RULE_PROTO | RULE_PORT | RULE_EXE | RULE_DIR,
            addr: v4([1, 1, 1, 0]),
            family: 4,
            prefix: 24,
            proto: IPPROTO_TCP,
            port_lo: 443,
            port_hi: 444,
            exe: 3,
            dir: DIR_OUT,
            ..any
        };
        assert!(rule_matches(&r, 4, &dst, IPPROTO_TCP, 444, 3, DIR_OUT));
        assert!(!rule_matches(&r, 6, &dst, IPPROTO_TCP, 443, 3, DIR_OUT), "family");
        assert!(!rule_matches(&r, 4, &v4([1, 1, 2, 1]), IPPROTO_TCP, 443, 3, DIR_OUT), "net");
        assert!(!rule_matches(&r, 4, &dst, IPPROTO_UDP, 443, 3, DIR_OUT), "proto");
        assert!(!rule_matches(&r, 4, &dst, IPPROTO_TCP, 445, 3, DIR_OUT), "port");
        assert!(!rule_matches(&r, 4, &dst, IPPROTO_TCP, 443, 4, DIR_OUT), "exe");
        assert!(!rule_matches(&r, 4, &dst, IPPROTO_TCP, 443, 0, DIR_OUT), "unknown exe");
        assert!(!rule_matches(&r, 4, &dst, IPPROTO_TCP, 443, 3, DIR_IN), "direction");
        let port = RuleEntry { fields: RULE_PORT, port_lo: 1, port_hi: 65535, ..any };
        assert!(!rule_matches(&port, 4, &dst, IPPROTO_TCP, 0, 0, DIR_OUT), "unknown port");
    }

    #[test]
    fn conn_key_from_flow() {
        let mut k = FlowKey { family: 6, proto: IPPROTO_UDP, local_port: 5353, remote_port: 53, ifindex: 3, ..Default::default() };
        k.remote_addr[10] = 0xff;
        k.remote_addr[11] = 0xff;
        k.remote_addr[12..].copy_from_slice(&[9, 9, 9, 9]);
        k.local_addr[0] = 1;
        let c = ConnKey::from_flow(&k);
        assert_eq!((c.family, c.remote_addr, c.local_port, c.remote_port), (4, v4([9, 9, 9, 9]), 5353, 53));
        k.ifindex = 7;
        k.local_addr[0] = 2;
        assert_eq!(ConnKey::from_flow(&k), c, "no interface or local address in the key");
        assert!(is_dhcp(IPPROTO_UDP, 68, 67) && is_dhcp(IPPROTO_UDP, 546, 547));
        assert!(!is_dhcp(IPPROTO_TCP, 68, 67), "UDP only");
        assert!(!is_dhcp(IPPROTO_UDP, 5432, 67), "source port 67 to another port");
        assert!(!is_dhcp(IPPROTO_UDP, 67, 68), "not a DHCP server");
        assert!(is_unparsed(6, 60) && is_unparsed(6, 44) && !is_unparsed(6, IPPROTO_TCP) && !is_unparsed(4, 0));
    }

    #[test]
    fn mapped_v4_is_unmapped() {
        let mut m = [0u8; 16];
        m[10] = 0xff;
        m[11] = 0xff;
        m[12..].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(unmap_v4(6, &m), (4, v4([1, 2, 3, 4])));
        m[9] = 1;
        assert_eq!(unmap_v4(6, &m), (6, m));
        assert_eq!(unmap_v4(4, &v4([1, 2, 3, 4])), (4, v4([1, 2, 3, 4])));
    }

    const TCP_V4: [u8; 54] = {
        let mut b = [0u8; 54];
        // Ethernet: dst, src, type 0x0800
        b[12] = 0x08;
        // IPv4: ver 4, ihl 5, proto TCP, 10.0.0.2 -> 1.1.1.1
        b[14] = 0x45;
        b[23] = 6;
        b[26] = 10;
        b[29] = 2;
        b[30] = 1;
        b[31] = 1;
        b[32] = 1;
        b[33] = 1;
        // TCP ports 40000 -> 443
        b[34] = 0x9c;
        b[35] = 0x40;
        b[36] = 0x01;
        b[37] = 0xbb;
        b
    };

    #[test]
    fn parses_ipv4_tcp_behind_ethernet() {
        let p = parse_packet(&&TCP_V4[..], 14, ETH_P_IP).unwrap();
        assert_eq!(p.family, 4);
        assert_eq!(p.proto, IPPROTO_TCP);
        assert_eq!(&p.src[..4], &[10, 0, 0, 2]);
        assert_eq!(&p.dst[..4], &[1, 1, 1, 1]);
        assert_eq!((p.sport, p.dport), (40000, 443));
    }

    #[test]
    fn payload_offset() {
        let mut b = TCP_V4;
        assert_eq!(parse_packet(&&b[..], 14, ETH_P_IP).unwrap().payload, 0, "bad data offset");
        b[46] = 0x50; // 20-byte TCP header
        assert_eq!(parse_packet(&&b[..], 14, ETH_P_IP).unwrap().payload, 54);
        b[46] = 0x80; // 32 bytes with options
        assert_eq!(parse_packet(&&b[..], 14, ETH_P_IP).unwrap().payload, 66);
        b[23] = IPPROTO_UDP;
        assert_eq!(parse_packet(&&b[..], 14, ETH_P_IP).unwrap().payload, 42);
        assert_eq!(parse_packet(&&b[14..], 0, ETH_P_IP).unwrap().payload, 28);
    }

    #[test]
    fn parses_ipv4_without_l2_header() {
        let p = parse_packet(&&TCP_V4[14..], 0, ETH_P_IP).unwrap();
        assert_eq!((p.sport, p.dport), (40000, 443));
    }

    #[test]
    fn ipv4_fragment_has_no_ports() {
        let mut b = TCP_V4;
        b[21] = 0x10; // fragment offset != 0
        let p = parse_packet(&&b[..], 14, ETH_P_IP).unwrap();
        assert_eq!((p.sport, p.dport), (0, 0));
    }

    #[test]
    fn parses_ipv6_udp() {
        let mut b = [0u8; 48];
        b[0] = 0x60;
        b[6] = IPPROTO_UDP;
        b[23] = 1; // src ::1
        b[39] = 2; // dst ::2
        b[40..44].copy_from_slice(&[0x00, 0x35, 0xd4, 0x31]); // 53 -> 54321
        let p = parse_packet(&&b[..], 0, ETH_P_IPV6).unwrap();
        assert_eq!(p.family, 6);
        assert_eq!(p.src[15], 1);
        assert_eq!(p.dst[15], 2);
        assert_eq!((p.sport, p.dport), (53, 54321));
    }

    #[test]
    fn truncated_and_unknown_return_none() {
        assert!(parse_packet(&&TCP_V4[..20], 14, ETH_P_IP).is_none());
        assert!(parse_packet(&&TCP_V4[..], 14, 0x0806).is_none());
    }

    #[test]
    fn flow_key_swaps_on_ingress() {
        let p = parse_packet(&&TCP_V4[..], 14, ETH_P_IP).unwrap();
        let eg = FlowKey::from_packet(&p, 3, true);
        let mut reply = p;
        core::mem::swap(&mut reply.src, &mut reply.dst);
        core::mem::swap(&mut reply.sport, &mut reply.dport);
        let ing = FlowKey::from_packet(&reply, 3, false);
        assert_eq!(eg, ing);
        assert_eq!(eg.local_port, 40000);
    }

    #[test]
    fn reversed_swaps_ends() {
        let p = parse_packet(&&TCP_V4[..], 14, ETH_P_IP).unwrap();
        let eg = FlowKey::from_packet(&p, 1, true);
        let ing = FlowKey::from_packet(&p, 1, false);
        assert_eq!(eg.reversed(), ing);
        assert_eq!(eg.reversed().reversed(), eg);
    }

    /// TCP_V4 with VLAN tags inserted after the MAC addresses.
    fn tagged(tpids: &[u16]) -> ([u8; 128], usize, u16) {
        let mut b = [0u8; 128];
        let mut n = 12;
        for (i, t) in tpids.iter().enumerate() {
            b[n..n + 2].copy_from_slice(&t.to_be_bytes());
            b[n + 2..n + 4].copy_from_slice(&(100 + i as u16).to_be_bytes());
            n += 4;
        }
        b[n..n + 42].copy_from_slice(&TCP_V4[12..54]);
        (b, n + 42, tpids[0])
    }

    #[test]
    fn vlan_tags_are_skipped() {
        for tpids in [&[ETH_P_8021Q][..], &[ETH_P_8021AD, ETH_P_8021Q][..]] {
            let (b, len, et) = tagged(tpids);
            // skb->protocol is the outer tag; l3_offset points after it.
            let p = parse_packet(&&b[..len], 14, et).unwrap();
            assert_eq!((p.family, p.sport, p.dport), (4, 40000, 443), "{tpids:x?}");
        }
        // Three tags are more than followed: no IP header found.
        let (b, len, et) = tagged(&[ETH_P_8021AD, ETH_P_8021Q, ETH_P_8021Q]);
        assert!(parse_packet(&&b[..len], 14, et).is_none());
    }

    /// IPv6 TCP 40000 -> 443 behind the given extension headers.
    fn ipv6_with(ext: &[(u8, &[u8])]) -> ([u8; 256], usize) {
        let mut b = [0u8; 256];
        b[14] = 0x60;
        b[14 + 6] = ext.first().map_or(IPPROTO_TCP, |e| e.0);
        let mut n = 54;
        for (i, (_, body)) in ext.iter().enumerate() {
            b[n..n + body.len()].copy_from_slice(body);
            b[n] = ext.get(i + 1).map_or(IPPROTO_TCP, |e| e.0);
            n += body.len();
        }
        b[n..n + 2].copy_from_slice(&40000u16.to_be_bytes());
        b[n + 2..n + 4].copy_from_slice(&443u16.to_be_bytes());
        (b, n + 20)
    }

    #[test]
    fn ipv6_extension_headers_are_followed() {
        let hop = [0u8; 8];
        let mut dst = [0u8; 16];
        dst[1] = 1; // 16 bytes
        let mut ah = [0u8; 12];
        ah[1] = 1; // (1 + 2) * 4 = 12 bytes
        let frag_first = [0u8; 8];
        let (b, len) = ipv6_with(&[(0, &hop), (60, &dst), (51, &ah), (44, &frag_first)]);
        let p = parse_packet(&&b[..len], 14, ETH_P_IPV6).unwrap();
        assert_eq!((p.family, p.proto, p.sport, p.dport), (6, IPPROTO_TCP, 40000, 443));
    }

    #[test]
    fn ipv6_non_first_fragment_has_no_ports() {
        let mut frag = [0u8; 8];
        frag[2..4].copy_from_slice(&(185u16 << 3).to_be_bytes());
        let (b, len) = ipv6_with(&[(44, &frag)]);
        let p = parse_packet(&&b[..len], 14, ETH_P_IPV6).unwrap();
        assert_eq!((p.proto, p.sport, p.dport), (IPPROTO_TCP, 0, 0));
    }

    #[test]
    fn truncated_extension_header_fails_open() {
        let (b, _) = ipv6_with(&[(0, &[0u8; 8])]);
        // Cut inside the hop-by-hop header: still counted, no ports.
        let p = parse_packet(&&b[..14 + 40 + 1], 14, ETH_P_IPV6).unwrap();
        assert_eq!((p.family, p.proto, p.sport), (6, 0, 0));
    }

    #[test]
    fn too_many_extension_headers_stop_the_walk() {
        let hop = [0u8; 8];
        let ext = [(60u8, &hop[..]); MAX_IPV6_EXT + 1];
        let (b, len) = ipv6_with(&ext);
        let p = parse_packet(&&b[..len], 14, ETH_P_IPV6).unwrap();
        assert_eq!((p.proto, p.sport), (60, 0));
    }

    #[test]
    fn loopback_detection() {
        let v4 = |a: [u8; 4]| {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&a);
            b
        };
        assert!(is_loopback(4, &v4([127, 0, 0, 53])));
        assert!(!is_loopback(4, &v4([10, 0, 0, 1])));
        let mut one = [0u8; 16];
        one[15] = 1;
        assert!(is_loopback(6, &one));
        let mut mapped = [0u8; 16];
        mapped[10..16].copy_from_slice(&[0xff, 0xff, 127, 0, 0, 1]);
        assert!(is_loopback(6, &mapped));
        mapped[12] = 10;
        assert!(!is_loopback(6, &mapped));
        let mut fe80 = one;
        fe80[0] = 0xfe;
        assert!(!is_loopback(6, &fe80));
    }
}

