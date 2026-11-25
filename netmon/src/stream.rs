//! Follow stream: the payload of one TCP connection from a capture, per
//! direction, in arrival order. A byte sent twice (retransmit) shows once;
//! a hole (a packet the capture lost, or a segment cut at the capture
//! length) shows as a "missing" marker.

use std::net::{IpAddr, SocketAddr};

use crate::capture::Captured;

/// One TCP segment of a frame.
#[derive(Debug, PartialEq)]
struct Segment<'a> {
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    syn: bool,
    ack: bool,
    fin: bool,
    payload: &'a [u8],
    /// Payload bytes the frame had on the wire beyond the captured ones.
    cut: u32,
}

/// The TCP segment of an Ethernet frame (IPv4 or IPv6 without extension
/// headers; VLAN tags skipped).
fn segment(data: &[u8], orig_len: u32) -> Option<Segment<'_>> {
    let be16 = |i: usize| data.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let mut off = 12;
    let mut et = be16(off)?;
    while et == 0x8100 || et == 0x88a8 {
        off += 4;
        et = be16(off)?;
    }
    let l3 = off + 2;
    let (src, dst, l4, ip_end) = match et {
        0x0800 => {
            let b = data.get(l3..l3 + 20)?;
            if b[9] != 6 || u16::from_be_bytes([b[6], b[7]]) & 0x1fff != 0 {
                return None;
            }
            let total = u16::from_be_bytes([b[2], b[3]]) as usize;
            let src = IpAddr::from([b[12], b[13], b[14], b[15]]);
            let dst = IpAddr::from([b[16], b[17], b[18], b[19]]);
            (src, dst, l3 + (b[0] & 0x0f) as usize * 4, l3 + total)
        }
        0x86dd => {
            let b = data.get(l3..l3 + 40)?;
            if b[6] != 6 {
                return None;
            }
            let plen = u16::from_be_bytes([b[4], b[5]]) as usize;
            let a = |i: usize| -> [u8; 16] { b[i..i + 16].try_into().unwrap_or([0; 16]) };
            (IpAddr::from(a(8)), IpAddr::from(a(24)), l3 + 40, l3 + 40 + plen)
        }
        _ => return None,
    };
    let t = data.get(l4..l4 + 20)?;
    let sport = u16::from_be_bytes([t[0], t[1]]);
    let dport = u16::from_be_bytes([t[2], t[3]]);
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let flags = t[13];
    let start = l4 + (t[12] >> 4) as usize * 4;
    // The IP length says where the payload ends; Ethernet padding is not
    // payload. The capture may hold less.
    let wire_end = ip_end.max(start);
    let end = wire_end.min(data.len());
    let payload = data.get(start..end).unwrap_or(&[]);
    // A frame cut at the capture length: the wire had more bytes.
    let on_wire = (orig_len as usize).min(wire_end);
    let cut = on_wire.saturating_sub(end.max(start)) as u32;
    Some(Segment {
        src: SocketAddr::new(src, sport),
        dst: SocketAddr::new(dst, dport),
        seq,
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
        fin: flags & 0x01 != 0,
        payload,
        cut,
    })
}

/// A piece of the stream: who sent it, and its bytes or a marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Piece {
    Data { client: bool, bytes: Vec<u8> },
    Missing { client: bool, bytes: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub pieces: Vec<Piece>,
    /// Payload bytes per direction (client, server).
    pub bytes: (u64, u64),
}

/// The stream of the TCP connection of `packets[at]`, or None if that
/// packet is not TCP.
pub fn follow<'a>(packets: impl IntoIterator<Item = &'a Captured>, at: &Captured) -> Option<Stream> {
    let first = segment(&at.data, at.orig_len)?;
    let same = |s: &Segment| (s.src == first.src && s.dst == first.dst) || (s.src == first.dst && s.dst == first.src);
    let segs: Vec<Segment> =
        packets.into_iter().filter_map(|p| segment(&p.data, p.orig_len)).filter(|s| same(s)).collect();
    // The client sent the SYN without ACK; without one, the first sender.
    let client = segs.iter().find(|s| s.syn && !s.ack).map(|s| s.src).unwrap_or(segs.first()?.src);
    let server = if first.src == client { first.dst } else { first.src };
    let mut st = Reassembly::default();
    // A segment that starts after a gap waits: a segment that was captured
    // but arrived out of order can still fill the gap.
    let mut held: [Vec<&Segment>; 2] = [Vec::new(), Vec::new()];
    for s in &segs {
        let from_client = s.src == client;
        let d = usize::from(!from_client);
        if st.ahead(d, s) > 0 {
            held[d].push(s);
            // A real gap: do not hold the rest of the stream behind it.
            if held[d].len() > MAX_HELD {
                let i = (0..held[d].len()).min_by_key(|&i| st.ahead(d, held[d][i])).unwrap_or(0);
                let h = held[d].remove(i);
                st.feed(d, from_client, h);
            } else {
                continue;
            }
        } else {
            st.feed(d, from_client, s);
        }
        // Segments that now follow on (or overlap) the stream go next.
        while let Some(i) = held[d].iter().position(|h| st.ahead(d, h) <= 0) {
            let h = held[d].remove(i);
            st.feed(d, from_client, h);
        }
    }
    // What is still held starts after a real gap: in sequence order.
    for (d, rest) in held.iter_mut().enumerate() {
        while !rest.is_empty() {
            let i = (0..rest.len()).min_by_key(|&i| st.ahead(d, rest[i])).unwrap_or(0);
            let h = rest.remove(i);
            st.feed(d, d == 0, h);
        }
    }
    let Reassembly { pieces, bytes, .. } = st;
    Some(Stream { client, server, pieces, bytes })
}

/// Segments held per direction while they wait for a gap to fill.
const MAX_HELD: usize = 8;

/// The state of `follow`: next expected sequence number per direction
/// (client, server), the pieces so far and the payload bytes.
#[derive(Default)]
struct Reassembly {
    next: [Option<u32>; 2],
    pieces: Vec<Piece>,
    bytes: (u64, u64),
}

impl Reassembly {
    fn start(s: &Segment) -> u32 {
        s.seq.wrapping_add(u32::from(s.syn))
    }

    /// How far the segment starts after (positive) or before the next
    /// expected byte; wrapping keeps it right across 2^32.
    fn ahead(&self, d: usize, s: &Segment) -> i32 {
        let seq = Self::start(s);
        self.next[d].map_or(0, |n| seq.wrapping_sub(n) as i32)
    }

    fn feed(&mut self, d: usize, from_client: bool, s: &Segment) {
        let seq = Self::start(s);
        let len = s.payload.len() as u32 + s.cut;
        let n = *self.next[d].get_or_insert(seq);
        let ahead = seq.wrapping_sub(n) as i32;
        let (skip, gap) = if ahead >= 0 { (0u32, ahead as u32) } else { ((-ahead) as u32, 0) };
        if gap > 0 {
            push(&mut self.pieces, Piece::Missing { client: from_client, bytes: gap });
        }
        if skip < len {
            let new = &s.payload[(skip as usize).min(s.payload.len())..];
            if !new.is_empty() {
                push(&mut self.pieces, Piece::Data { client: from_client, bytes: new.to_vec() });
                if from_client { self.bytes.0 += new.len() as u64 } else { self.bytes.1 += new.len() as u64 }
            }
            let cut = s.cut.min(len - skip);
            if cut > 0 {
                push(&mut self.pieces, Piece::Missing { client: from_client, bytes: cut });
            }
        }
        // The FIN takes one sequence number, also without payload.
        let end = seq.wrapping_add(len).wrapping_add(u32::from(s.fin));
        if end.wrapping_sub(n) as i32 > 0 {
            self.next[d] = Some(end);
        }
    }
}

/// Appends, joining with the previous piece of the same kind and side.
fn push(pieces: &mut Vec<Piece>, p: Piece) {
    match (pieces.last_mut(), p) {
        (Some(Piece::Data { client: a, bytes }), Piece::Data { client: b, bytes: more }) if *a == b => bytes.extend(more),
        (Some(Piece::Missing { client: a, bytes }), Piece::Missing { client: b, bytes: more }) if *a == b => *bytes += more,
        (_, p) => pieces.push(p),
    }
}

/// Bytes as text: printable ASCII and line breaks stay, `\r` goes, every
/// other byte is `.`.
pub fn text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .filter(|b| **b != b'\r')
        .map(|&b| if b == b'\n' || b == b'\t' || (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
}

/// Does the stream start like TLS (a handshake record)?
pub fn looks_like_tls(s: &Stream) -> bool {
    s.pieces.iter().find_map(|p| match p {
        Piece::Data { bytes, .. } => Some(bytes.len() >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03),
        Piece::Missing { .. } => None,
    }) == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::RawPacket;
    use std::time::SystemTime;

    /// An IPv4 TCP frame from 10.0.0.2:40000 (client) or 1.1.1.1:80.
    fn frame(client: bool, seq: u32, flags: u8, payload: &[u8]) -> Captured {
        let mut d = vec![0u8; 12];
        d.extend_from_slice(&[0x08, 0x00]);
        let total = (20 + 20 + payload.len()) as u16;
        let (src, dst) = if client { ([10, 0, 0, 2], [1, 1, 1, 1]) } else { ([1, 1, 1, 1], [10, 0, 0, 2]) };
        let (sport, dport) = if client { (40000u16, 80u16) } else { (80, 40000) };
        d.extend_from_slice(&[0x45, 0]);
        d.extend_from_slice(&total.to_be_bytes());
        d.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]);
        d.extend_from_slice(&src);
        d.extend_from_slice(&dst);
        d.extend_from_slice(&sport.to_be_bytes());
        d.extend_from_slice(&dport.to_be_bytes());
        d.extend_from_slice(&seq.to_be_bytes());
        d.extend_from_slice(&[0, 0, 0, 0, 0x50, flags, 0, 0, 0, 0, 0, 0]);
        d.extend_from_slice(payload);
        let orig_len = d.len() as u32;
        Captured::from_raw(RawPacket { time: SystemTime::now(), ifindex: 1, egress: client, orig_len, data: d })
    }

    fn data(s: &Stream) -> Vec<(bool, String)> {
        s.pieces
            .iter()
            .map(|p| match p {
                Piece::Data { client, bytes } => (*client, text(bytes)),
                Piece::Missing { client, bytes } => (*client, format!("[{bytes} missing]")),
            })
            .collect()
    }

    #[test]
    fn follows_both_directions_and_drops_retransmits() {
        let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let p = [
            frame(true, 1000, 0x02, b""),
            frame(false, 5000, 0x12, b""),
            frame(true, 1001, 0x18, req),
            frame(true, 1001, 0x18, req),
            frame(false, 5001, 0x18, b"HTTP/1.1 200 OK\r\n\r\nhel"),
            frame(false, 5001 + 22, 0x18, b"lo"),
            frame(false, 5001 + 24, 0x11, b""),
        ];
        let mut p = Vec::from(p);
        // The client's FIN, then its last ACK one number later: no hole.
        p.push(frame(true, 1001 + req.len() as u32, 0x11, b""));
        p.push(frame(true, 1002 + req.len() as u32, 0x10, b""));
        let s = follow(p.iter(), &p[4]).unwrap();
        assert_eq!(s.client, "10.0.0.2:40000".parse().unwrap());
        assert_eq!(
            data(&s),
            [(true, "GET / HTTP/1.1\nHost: x\n\n".to_string()), (false, "HTTP/1.1 200 OK\n\nhello".to_string())]
        );
        assert_eq!(s.bytes, (req.len() as u64, 24));
    }

    #[test]
    fn holes_and_cut_segments_show_as_missing() {
        let mut cut = frame(false, 5011, 0x18, b"abcdef");
        // On the wire the segment had 4 more bytes than captured.
        cut.orig_len += 4;
        let ip_len = u16::from_be_bytes([cut.data[16], cut.data[17]]) + 4;
        cut.data[16..18].copy_from_slice(&ip_len.to_be_bytes());
        let p = [frame(false, 5001, 0x18, b"0123"), cut, frame(false, 5021, 0x18, b"z")];
        let s = follow(p.iter(), &p[0]).unwrap();
        assert_eq!(
            data(&s),
            [(true, "0123".to_string()), (true, "[6 missing]".to_string()), (true, "abcdef".to_string()), (true, "[4 missing]".to_string()), (true, "z".to_string())],
            "no SYN: the first sender counts as client"
        );
    }

    #[test]
    fn segments_out_of_order_are_no_holes() {
        // 0123 and abcd were captured in the wrong order; z after a real gap.
        let p = [
            frame(true, 1000, 0x02, b""),
            frame(true, 1005, 0x18, b"abcd"),
            frame(true, 1001, 0x18, b"0123"),
            frame(false, 9, 0x18, b"ok"),
            frame(true, 1019, 0x18, b"z"),
        ];
        let s = follow(p.iter(), &p[1]).unwrap();
        assert_eq!(
            data(&s),
            [(true, "0123abcd".to_string()), (false, "ok".to_string()), (true, "[10 missing]".to_string()), (true, "z".to_string())]
        );
        assert_eq!(s.bytes, (9, 2));
    }

    #[test]
    fn view_lines_split_text_and_name_holes() {
        let p = [frame(true, 1000, 0x02, b""), frame(true, 1001, 0x18, b"a\r\nb"), frame(false, 9, 0x18, b"ok")];
        let v = crate::client::stream_view(&follow(p.iter(), &p[1]).unwrap());
        assert_eq!(v.lines, [(Some(true), "a".to_string()), (Some(true), "b".to_string()), (Some(false), "ok".to_string())]);
        assert!(v.title.contains("10.0.0.2:40000 (client, red, 4 bytes)"), "{}", v.title);
        let tls = [frame(true, 1, 0x18, &[0x16, 0x03, 0x01, 0, 1, 1])];
        let v = crate::client::stream_view(&follow(tls.iter(), &tls[0]).unwrap());
        assert!(v.lines[0].1.starts_with("TLS: the payload is encrypted"));
    }

    /// Follows a real recorded HTTP exchange when NETMON_STREAM_PCAP names
    /// a classic pcap file; else it does nothing.
    #[test]
    fn real_capture_when_present() {
        let Some(path) = std::env::var_os("NETMON_STREAM_PCAP") else { return };
        let b = std::fs::read(path).unwrap();
        let mut packets = Vec::new();
        let mut i = 24;
        while i + 16 <= b.len() {
            let len = u32::from_le_bytes(b[i + 8..i + 12].try_into().unwrap()) as usize;
            let orig = u32::from_le_bytes(b[i + 12..i + 16].try_into().unwrap());
            let data = b[i + 16..i + 16 + len].to_vec();
            packets.push(Captured::from_raw(RawPacket { time: SystemTime::now(), ifindex: 1, egress: true, orig_len: orig, data }));
            i += 16 + len;
        }
        let s = follow(packets.iter(), &packets[0]).unwrap();
        let v = crate::client::stream_view(&s);
        let side = |c: bool| v.lines.iter().filter(|(x, _)| *x == Some(c)).map(|(_, l)| l.as_str()).collect::<Vec<_>>().join("\n");
        eprintln!("{}\n--- client ---\n{}\n--- server (first lines) ---\n{}", v.title, side(true), side(false).lines().take(12).collect::<Vec<_>>().join("\n"));
        assert!(side(true).starts_with("GET /COPYING HTTP/1.1"));
        assert!(side(false).contains("200 OK") && side(false).contains("COPYRIGHT AND PERMISSION NOTICE"));
        let notes: Vec<_> = v.lines.iter().filter(|(x, _)| x.is_none()).collect();
        assert!(notes.is_empty(), "nothing missing: {notes:?}");
    }

    #[test]
    fn sequence_numbers_wrap_and_tls_is_seen() {
        let p = [frame(true, u32::MAX - 1, 0x18, &[0x16, 0x03, 0x01, 0, 5]), frame(true, 3, 0x18, b"x")];
        let s = follow(p.iter(), &p[0]).unwrap();
        assert!(looks_like_tls(&s));
        assert_eq!(s.bytes.0, 6, "the second segment continues across 2^32");
        let udp = {
            let mut f = frame(true, 1, 0x18, b"");
            f.data[23] = 17;
            f
        };
        assert!(follow([&udp], &udp).is_none(), "not TCP");
        assert_eq!(text(b"a\x00\x1bb\r\nc"), "a..b\nc");
    }
}
