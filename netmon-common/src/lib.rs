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
/// Block rules (remote networks and ports). Rule ids are 0..MAX_RULES and
/// index the per-rule drop counters.
pub const MAX_RULES: u32 = 1_024;
/// Lockout guard entries.
pub const MAX_GUARD: u32 = 64;

/// A remote port to block for one transport protocol.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PortKey {
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// A remote endpoint that is never blocked (SSH session, DNS resolver).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct GuardKey {
    pub addr: [u8; 16],
    pub port: u16,
    pub family: u8,
    pub _pad: u8,
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
unsafe impl aya::Pod for PortKey {}
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

