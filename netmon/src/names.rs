//! Hostnames for remote addresses, from DNS answers the host receives.
//! The bytes come from the network and are untrusted: every read is
//! bounds-checked, name decoding follows at most a few compression
//! pointers, and a malformed packet yields what was parsed before the
//! error.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
/// Most answer records read from one packet.
const MAX_ANSWERS: usize = 64;
/// Most compression pointers followed in one name.
const MAX_POINTERS: usize = 16;
const MAX_NAME: usize = 253;

fn u16_at(p: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]))
}

/// Reads the name at `off`. Returns it and the offset after it in the
/// record (after the first pointer, if the name uses one).
fn read_name(p: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *p.get(off)? as usize;
        match len & 0xc0 {
            0x00 if len == 0 => {
                return Some((name, end.unwrap_or(off + 1)));
            }
            0x00 => {
                let label = p.get(off + 1..off + 1 + len)?;
                if !name.is_empty() {
                    name.push('.');
                }
                // Hostnames are ASCII; anything else is shown escaped.
                for &b in label {
                    if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                        name.push((b as char).to_ascii_lowercase());
                    } else {
                        name.push_str(&format!("\\{b:03}"));
                    }
                }
                if name.len() > MAX_NAME * 4 {
                    return None;
                }
                off += 1 + len;
            }
            0xc0 => {
                jumps += 1;
                if jumps > MAX_POINTERS {
                    return None;
                }
                let target = (u16_at(p, off)? & 0x3fff) as usize;
                end.get_or_insert(off + 2);
                off = target;
            }
            // 0x40 and 0x80 are reserved label types.
            _ => return None,
        }
    }
}

/// Addresses in the A/AAAA answers of a DNS response, each with the name
/// that was asked (not the CNAME target: `www.example.com`, not the CDN
/// name) and its TTL.
pub fn dns_answers(p: &[u8]) -> Vec<(IpAddr, String, u32)> {
    let mut out = Vec::new();
    let (Some(flags), Some(qd), Some(an)) = (u16_at(p, 2), u16_at(p, 4), u16_at(p, 6)) else { return out };
    // Response, rcode 0 (no error), exactly one question.
    if flags & 0x8000 == 0 || flags & 0x000f != 0 || qd != 1 {
        return out;
    }
    let Some((asked, mut off)) = read_name(p, 12) else { return out };
    off += 4; // qtype, qclass
    if asked.is_empty() {
        return out;
    }
    for _ in 0..(an as usize).min(MAX_ANSWERS) {
        let Some((_, after)) = read_name(p, off) else { break };
        let (Some(ty), Some(ttl_hi), Some(ttl_lo), Some(rdlen)) =
            (u16_at(p, after), u16_at(p, after + 4), u16_at(p, after + 6), u16_at(p, after + 8))
        else {
            break;
        };
        let data = after + 10;
        let Some(rdata) = p.get(data..data + rdlen as usize) else { break };
        let ttl = (ttl_hi as u32) << 16 | ttl_lo as u32;
        let ip = match (ty, rdata.len()) {
            (TYPE_A, 4) => Some(IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))),
            (TYPE_AAAA, 16) => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(rdata).unwrap()))),
            _ => None,
        };
        if let Some(ip) = ip {
            out.push((ip, asked.clone(), ttl));
        }
        off = data + rdlen as usize;
    }
    out
}

/// Names kept at most.
const MAX_HOSTS: usize = 4096;
/// How long a name stays after its last answer. DNS TTLs are often a
/// minute, connections live much longer.
const KEEP: Duration = Duration::from_secs(3600);

/// Remote address -> hostname from DNS answers.
#[derive(Default)]
pub struct HostNames {
    by_ip: HashMap<IpAddr, (String, Instant)>,
}

impl HostNames {
    pub fn insert(&mut self, ip: IpAddr, name: String, now: Instant) {
        if self.by_ip.len() >= MAX_HOSTS && !self.by_ip.contains_key(&ip) {
            self.by_ip.retain(|_, (_, t)| now.duration_since(*t) < KEEP);
            if self.by_ip.len() >= MAX_HOSTS {
                // Still full: drop the oldest entry.
                if let Some(old) = self.by_ip.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| *k) {
                    self.by_ip.remove(&old);
                }
            }
        }
        self.by_ip.insert(ip, (name, now));
    }

    pub fn get(&self, ip: IpAddr, now: Instant) -> Option<&str> {
        self.by_ip.get(&ip).filter(|(_, t)| now.duration_since(*t) < KEEP).map(|(n, _)| n.as_str())
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_ip.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Response for www.example.com: a CNAME, then A and AAAA records whose
    /// owner names are compression pointers.
    fn response() -> Vec<u8> {
        let mut p = vec![
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0, // header: response, 1 question, 3 answers
        ];
        // Question at 12: www.example.com A IN
        p.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
        // CNAME: www.example.com -> cdn.example.net
        p.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 17]);
        p.extend_from_slice(b"\x03cdn\x07example\x03net\x00");
        // A at pointer to the CNAME target (offset 45): 93.184.215.14, ttl 300
        p.extend_from_slice(&[0xc0, 45, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 215, 14]);
        // AAAA 2001:db8::1, ttl 70000
        p.extend_from_slice(&[0xc0, 45, 0, 28, 0, 1, 0, 1, 0x11, 0x70, 0, 16]);
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p
    }

    #[test]
    fn answers_map_to_the_asked_name() {
        let got = dns_answers(&response());
        assert_eq!(
            got,
            vec![
                ("93.184.215.14".parse().unwrap(), "www.example.com".into(), 300),
                ("2001:db8::1".parse().unwrap(), "www.example.com".into(), 70000),
            ]
        );
    }

    #[test]
    fn truncated_response_keeps_complete_answers() {
        let full = response();
        // Cut inside the AAAA record: the A record survives.
        let got = dns_answers(&full[..full.len() - 5]);
        assert_eq!(got.len(), 1);
        // Every prefix parses without panicking.
        for n in 0..full.len() {
            let _ = dns_answers(&full[..n]);
        }
    }

    #[test]
    fn malformed_input_is_refused() {
        let mut q = response();
        q[2] = 0x01; // a query, not a response
        assert!(dns_answers(&q).is_empty());
        let mut e = response();
        e[3] = 0x83; // NXDOMAIN
        assert!(dns_answers(&e).is_empty());
        // A pointer loop in the question name.
        let mut l = response();
        l[12] = 0xc0;
        l[13] = 12;
        assert!(dns_answers(&l).is_empty());
        // Reserved label type.
        let mut r = response();
        r[12] = 0x40;
        assert!(dns_answers(&r).is_empty());
        // Wrong rdlength for an A record is skipped, not misread.
        let mut w = response();
        let a = w.iter().position(|&b| b == 93).unwrap() - 1;
        w[a] = 3;
        assert!(dns_answers(&w).iter().all(|(ip, _, _)| ip.is_ipv6() || ip.to_string() != "93.184.215.14"));
        // Random bytes never panic.
        let mut x: u32 = 12345;
        for _ in 0..20_000 {
            let len = (x % 300) as usize;
            let mut b = Vec::with_capacity(len);
            for _ in 0..len {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                b.push((x >> 16) as u8);
            }
            if b.len() > 3 {
                b[2] |= 0x80;
                b[3] &= 0xf0;
            }
            let _ = dns_answers(&b);
        }
    }

    #[test]
    fn odd_label_bytes_are_escaped() {
        let mut p = vec![0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        p.extend_from_slice(b"\x04a\x1bb.\x03com\x00\x00\x01\x00\x01");
        p.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        assert_eq!(dns_answers(&p)[0].1, "a\\027b\\046.com", "no terminal escapes in names");
    }

    #[test]
    fn cache_expires_and_stays_bounded() {
        let t0 = Instant::now();
        let mut h = HostNames::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        h.insert(ip, "a.example".into(), t0);
        assert_eq!(h.get(ip, t0 + Duration::from_secs(60)), Some("a.example"));
        assert_eq!(h.get(ip, t0 + KEEP), None);
        for i in 0..(MAX_HOSTS as u32 + 10) {
            h.insert(IpAddr::V4(i.into()), "x".into(), t0 + Duration::from_millis(i as u64));
        }
        assert_eq!(h.len(), MAX_HOSTS);
    }
}
