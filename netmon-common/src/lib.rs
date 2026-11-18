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

/// Parses the IP header at `l3_offset` and, for TCP and UDP, the ports.
/// `ethertype` is the host-order L3 protocol (`ETH_P_IP` or `ETH_P_IPV6`).
/// Other protocols return `None`. IPv6 extension headers are not followed:
/// such packets are counted with the extension header as `proto` and port 0.
#[inline(always)]
pub fn parse_packet<S: PacketSource>(s: &S, l3_offset: usize, ethertype: u16) -> Option<Packet> {
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
            p.proto = h[6];
            p.src.copy_from_slice(&h[8..24]);
            p.dst.copy_from_slice(&h[24..40]);
            l4_offset = l3_offset + 40;
            has_ports = true;
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
}
