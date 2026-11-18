//! Packet decoding for the capture view. Input always starts with an
//! Ethernet header (the capture code adds a dummy one for L3-only devices).

use std::{
    fmt::Write as _,
    net::{Ipv4Addr, Ipv6Addr},
};

/// One-line summary for the packet list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub info: String,
}

/// Summary plus one line per decoded header field, indented by layer.
#[derive(Clone, Debug, Default)]
pub struct Decoded {
    pub summary: Summary,
    pub lines: Vec<String>,
}

fn u16_at(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(i)?, *d.get(i + 1)?]))
}

fn u32_at(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(i..i + 4)?.try_into().ok()?))
}

fn mac(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

pub fn decode(data: &[u8]) -> Decoded {
    let mut d = Decoded::default();
    d.summary.proto = "?".into();
    if data.len() < 14 {
        d.lines.push(format!("truncated frame ({} bytes)", data.len()));
        return d;
    }
    let mut ethertype = u16_at(data, 12).unwrap_or(0);
    let mut off = 14;
    if data[..12].iter().any(|b| *b != 0) {
        d.lines.push(format!("Ethernet  {} → {}", mac(&data[6..12]), mac(&data[0..6])));
    } else {
        d.lines.push("Link      (no link-layer header on this device)".into());
    }
    if ethertype == 0x8100 || ethertype == 0x88a8 {
        let tci = u16_at(data, 14).unwrap_or(0);
        d.lines.push(format!("  VLAN    id {} prio {}", tci & 0x0fff, tci >> 13));
        ethertype = u16_at(data, 16).unwrap_or(0);
        off = 18;
    }
    let l3 = &data[off.min(data.len())..];
    match ethertype {
        0x0800 => ipv4(l3, &mut d),
        0x86dd => ipv6(l3, &mut d),
        0x0806 => arp(l3, &mut d),
        t => {
            d.summary.proto = format!("0x{t:04x}");
            d.lines.push(format!("  EtherType 0x{t:04x} (not decoded)"));
        }
    }
    d
}

fn arp(p: &[u8], d: &mut Decoded) {
    d.summary.proto = "ARP".into();
    if p.len() < 28 {
        d.lines.push("ARP (truncated)".into());
        return;
    }
    let op = u16_at(p, 6).unwrap_or(0);
    let spa = Ipv4Addr::new(p[14], p[15], p[16], p[17]);
    let tpa = Ipv4Addr::new(p[24], p[25], p[26], p[27]);
    d.summary.src = spa.to_string();
    d.summary.dst = tpa.to_string();
    d.summary.info = match op {
        1 => format!("Who has {tpa}? Tell {spa}"),
        2 => format!("{spa} is at {}", mac(&p[8..14])),
        o => format!("op {o}"),
    };
    d.lines.push(format!("ARP       op {op}  sender {} {spa}  target {} {tpa}", mac(&p[8..14]), mac(&p[18..24])));
}

fn ipv4(p: &[u8], d: &mut Decoded) {
    if p.len() < 20 {
        d.summary.proto = "IPv4".into();
        d.lines.push("IPv4 (truncated)".into());
        return;
    }
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    let total = u16_at(p, 2).unwrap_or(0);
    let id = u16_at(p, 4).unwrap_or(0);
    let flags_frag = u16_at(p, 6).unwrap_or(0);
    let proto = p[9];
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    d.summary.src = src.to_string();
    d.summary.dst = dst.to_string();
    let mut flags = Vec::new();
    if flags_frag & 0x4000 != 0 {
        flags.push("DF");
    }
    if flags_frag & 0x2000 != 0 {
        flags.push("MF");
    }
    let frag = (flags_frag & 0x1fff) * 8;
    d.lines.push(format!(
        "IPv4      {src} → {dst}  len {total}  ttl {}  id 0x{id:04x}  tos 0x{:02x}  flags [{}]  frag {frag}  hdr {ihl}B  csum 0x{:04x}",
        p[8],
        p[1],
        flags.join(","),
        u16_at(p, 10).unwrap_or(0)
    ));
    // IHL and total length come from the sender: never trust them to fit the
    // captured bytes.
    let end = (total as usize).max(ihl).min(p.len());
    if frag != 0 {
        d.summary.proto = "IPv4".into();
        d.summary.info = format!("fragment offset {frag}");
        return;
    }
    l4(proto, &p[ihl.min(end)..end], d);
}

fn ipv6(p: &[u8], d: &mut Decoded) {
    if p.len() < 40 {
        d.summary.proto = "IPv6".into();
        d.lines.push("IPv6 (truncated)".into());
        return;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap());
    d.summary.src = src.to_string();
    d.summary.dst = dst.to_string();
    let plen = u16_at(p, 4).unwrap_or(0);
    let flow = u32_at(p, 0).unwrap_or(0) & 0x000f_ffff;
    d.lines.push(format!("IPv6      {src} → {dst}  payload {plen}  hop limit {}  flow 0x{flow:05x}", p[7]));
    // Follow common extension headers: hop-by-hop, routing, dest options.
    let mut next = p[6];
    let mut off = 40;
    for _ in 0..4 {
        if !matches!(next, 0 | 43 | 60) || off + 8 > p.len() {
            break;
        }
        let len = (p[off + 1] as usize + 1) * 8;
        d.lines.push(format!("  ext hdr {next} ({len}B)"));
        next = p[off];
        off += len;
    }
    let end = (40 + plen as usize).clamp(off.min(p.len()), p.len());
    l4(next, &p[off.min(p.len())..end], d);
}

fn tcp_flags(f: u8) -> String {
    const NAMES: [(u8, &str); 8] = [
        (0x02, "SYN"),
        (0x10, "ACK"),
        (0x01, "FIN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ];
    NAMES.iter().filter(|(b, _)| f & b != 0).map(|(_, n)| *n).collect::<Vec<_>>().join(",")
}

fn l4(proto: u8, p: &[u8], d: &mut Decoded) {
    match proto {
        6 => tcp(p, d),
        17 => udp(p, d),
        1 | 58 => {
            d.summary.proto = if proto == 1 { "ICMP" } else { "ICMPv6" }.into();
            let (t, c) = (p.first().copied().unwrap_or(0), p.get(1).copied().unwrap_or(0));
            let name = match (proto, t) {
                (1, 0) | (58, 129) => "echo reply",
                (1, 8) | (58, 128) => "echo request",
                (1, 3) | (58, 1) => "destination unreachable",
                (1, 11) | (58, 3) => "time exceeded",
                (58, 133) => "router solicitation",
                (58, 134) => "router advertisement",
                (58, 135) => "neighbor solicitation",
                (58, 136) => "neighbor advertisement",
                _ => "",
            };
            d.summary.info = format!("type {t} code {c} {name}").trim_end().to_string();
            d.lines.push(format!("  {}  {}", d.summary.proto, d.summary.info));
        }
        other => {
            d.summary.proto = format!("ip/{other}");
            d.lines.push(format!("  protocol {other} (not decoded), {} bytes", p.len()));
        }
    }
}

fn tcp(p: &[u8], d: &mut Decoded) {
    d.summary.proto = "TCP".into();
    if p.len() < 20 {
        d.lines.push("  TCP (truncated)".into());
        return;
    }
    let (sp, dp) = (u16_at(p, 0).unwrap(), u16_at(p, 2).unwrap());
    let seq = u32_at(p, 4).unwrap();
    let ack = u32_at(p, 8).unwrap();
    let hlen = ((p[12] >> 4) as usize) * 4;
    let flags = tcp_flags(p[13]);
    let win = u16_at(p, 14).unwrap();
    let payload = p.len().saturating_sub(hlen);
    d.summary.src.push_str(&format!(":{sp}"));
    d.summary.dst.push_str(&format!(":{dp}"));
    d.summary.info = format!("[{flags}] seq {seq} ack {ack} win {win} len {payload}");
    d.lines.push(format!("  TCP     {sp} → {dp}  [{flags}]  seq {seq}  ack {ack}  win {win}  hdr {hlen}B  payload {payload}B"));
}

fn udp(p: &[u8], d: &mut Decoded) {
    d.summary.proto = "UDP".into();
    if p.len() < 8 {
        d.lines.push("  UDP (truncated)".into());
        return;
    }
    let (sp, dp) = (u16_at(p, 0).unwrap(), u16_at(p, 2).unwrap());
    let len = u16_at(p, 4).unwrap();
    d.summary.src.push_str(&format!(":{sp}"));
    d.summary.dst.push_str(&format!(":{dp}"));
    d.summary.info = format!("len {}", len.saturating_sub(8));
    d.lines.push(format!("  UDP     {sp} → {dp}  len {len}"));
    if sp == 53 || dp == 53 || sp == 5353 || dp == 5353 {
        dns(&p[8..], d);
    } else if sp == 443 || dp == 443 {
        d.summary.proto = "QUIC".into();
    }
}

fn dns(p: &[u8], d: &mut Decoded) {
    let (Some(id), Some(flags)) = (u16_at(p, 0), u16_at(p, 2)) else { return };
    let qd = u16_at(p, 4).unwrap_or(0);
    let an = u16_at(p, 6).unwrap_or(0);
    let response = flags & 0x8000 != 0;
    let name = if qd > 0 { qname(p, 12) } else { None };
    let qtype = name.as_ref().and_then(|(_, end)| u16_at(p, *end)).unwrap_or(0);
    let qtype = match qtype {
        1 => "A".to_string(),
        28 => "AAAA".into(),
        5 => "CNAME".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        t => t.to_string(),
    };
    let name = name.map(|(n, _)| n).unwrap_or_default();
    d.summary.proto = "DNS".into();
    d.summary.info = if response {
        format!("response 0x{id:04x} {qtype} {name}  answers {an}  rcode {}", flags & 0x000f)
    } else {
        format!("query 0x{id:04x} {qtype} {name}")
    };
    d.lines.push(format!("    DNS   {}", d.summary.info));
}

/// Reads an uncompressed DNS name at `off`. Returns the name and the offset
/// after it.
fn qname(p: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    for _ in 0..64 {
        let len = *p.get(off)? as usize;
        off += 1;
        if len == 0 {
            return Some((if name.is_empty() { ".".into() } else { name }, off));
        }
        if len & 0xc0 != 0 {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&crate::text::sanitize(&String::from_utf8_lossy(p.get(off..off + len)?)));
        off += len;
    }
    None
}

/// Classic hex dump: offset, 16 hex bytes, ASCII.
pub fn hexdump(data: &[u8]) -> Vec<String> {
    data.chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let mut line = format!("{:04x}  ", i * 16);
            for j in 0..16 {
                match chunk.get(j) {
                    Some(b) => write!(line, "{b:02x} ").unwrap(),
                    None => line.push_str("   "),
                }
                if j == 7 {
                    line.push(' ');
                }
            }
            line.push(' ');
            line.extend(chunk.iter().map(|b| if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' }));
            line
        })
        .collect()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Ethernet + IPv4 + TCP SYN 10.0.0.2:40000 -> 1.1.1.1:443.
    pub fn tcp_syn() -> Vec<u8> {
        let mut b = vec![0u8; 54];
        b[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        b[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        b[12..14].copy_from_slice(&[0x08, 0x00]);
        b[14] = 0x45;
        b[16..18].copy_from_slice(&40u16.to_be_bytes());
        b[22] = 64;
        b[23] = 6;
        b[26..30].copy_from_slice(&[10, 0, 0, 2]);
        b[30..34].copy_from_slice(&[1, 1, 1, 1]);
        b[34..36].copy_from_slice(&40000u16.to_be_bytes());
        b[36..38].copy_from_slice(&443u16.to_be_bytes());
        b[38..42].copy_from_slice(&1000u32.to_be_bytes());
        b[46] = 0x50;
        b[47] = 0x02;
        b[48..50].copy_from_slice(&64240u16.to_be_bytes());
        b
    }

    #[test]
    fn decodes_tcp_syn() {
        let d = decode(&tcp_syn());
        assert_eq!(d.summary.src, "10.0.0.2:40000");
        assert_eq!(d.summary.dst, "1.1.1.1:443");
        assert_eq!(d.summary.proto, "TCP");
        assert_eq!(d.summary.info, "[SYN] seq 1000 ack 0 win 64240 len 0");
        assert!(d.lines[0].starts_with("Ethernet  02:00:00:00:00:01 → aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn decodes_dns_query_without_l2() {
        // Dummy Ethernet header, IPv4, UDP 5000 -> 53, query A example.com
        let mut b = vec![0u8; 12];
        b.extend_from_slice(&[0x08, 0x00]);
        let dns: Vec<u8> = [
            &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0][..],
            &[7],
            b"example",
            &[3],
            b"com",
            &[0, 0, 1, 0, 1],
        ]
        .concat();
        let udp_len = 8 + dns.len() as u16;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(20 + udp_len).to_be_bytes());
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[10, 0, 0, 2]);
        ip[16..20].copy_from_slice(&[9, 9, 9, 9]);
        b.extend_from_slice(&ip);
        b.extend_from_slice(&5000u16.to_be_bytes());
        b.extend_from_slice(&53u16.to_be_bytes());
        b.extend_from_slice(&udp_len.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&dns);
        let d = decode(&b);
        assert_eq!(d.summary.proto, "DNS");
        assert_eq!(d.summary.info, "query 0x1234 A example.com");
        assert!(d.lines[0].contains("no link-layer"));
    }

    #[test]
    fn decodes_arp_request() {
        let mut b = vec![0xffu8; 6];
        b.extend_from_slice(&[2, 0, 0, 0, 0, 1, 0x08, 0x06]);
        let mut arp = vec![0u8; 28];
        arp[7] = 1;
        arp[8..14].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        arp[14..18].copy_from_slice(&[192, 168, 1, 10]);
        arp[24..28].copy_from_slice(&[192, 168, 1, 1]);
        b.extend_from_slice(&arp);
        let d = decode(&b);
        assert_eq!(d.summary.info, "Who has 192.168.1.1? Tell 192.168.1.10");
    }

    #[test]
    fn truncated_does_not_panic() {
        let full = tcp_syn();
        for n in 0..full.len() {
            let _ = decode(&full[..n]);
        }
    }

    #[test]
    fn ipv4_header_longer_than_capture_does_not_panic() {
        // IHL 15 (60-byte header) but only 40 bytes of L3 data.
        let mut b = tcp_syn();
        b[14] = 0x4f;
        let d = decode(&b);
        assert_eq!(d.summary.src, "10.0.0.2");
    }

    /// Deterministic fuzz: random bytes behind valid-looking Ethernet, IPv4,
    /// IPv6 and VLAN headers. The decoder must never panic.
    #[test]
    fn fuzz_random_frames_never_panic() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for i in 0..200_000 {
            let len = (next() % 200) as usize;
            let mut b: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if b.len() >= 15 {
                let (ty, ver): (&[u8], u8) = match i % 4 {
                    0 => (&[0x08, 0x00], 0x40),
                    1 => (&[0x86, 0xdd], 0x60),
                    2 => (&[0x81, 0x00], 0x40),
                    _ => (&[0x08, 0x06], 0x00),
                };
                b[12..14].copy_from_slice(ty);
                b[14] = ver | (b[14] & 0x0f);
            }
            let _ = decode(&b);
            let _ = hexdump(&b);
        }
    }

    #[test]
    fn dns_names_are_sanitized() {
        let mut p = vec![0u8; 12];
        p[5] = 1; // one question
        p.extend_from_slice(&[4, b'a', 0x1b, b'[', b'm', 0, 0, 1, 0, 1]);
        let (name, _) = qname(&p, 12).unwrap();
        assert_eq!(name, "a?[m");
    }

    #[test]
    fn hexdump_format() {
        let lines = hexdump(b"GET / HTTP/1.1\r\nHost");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "0000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..");
        assert!(lines[1].starts_with("0010  48 6f 73 74 "));
        assert!(lines[1].ends_with("Host"));
    }
}
