//! Display filters for the Capture tab: a small subset of the tcpdump
//! syntax. Terms: `tcp`, `udp`, `icmp`, `arp`, `ip`, `ip6`,
//! `[src|dst] port N`, `[src|dst] host IP`, `net CIDR`, and the shortcuts
//! `dns` (port 53), `http` (tcp port 80), `tls` (tcp port 443), `quic`
//! (udp port 443). `not` negates the next term; terms next to each other
//! and `and` must all match; `or` separates alternatives (`and` binds
//! first). No parentheses.

use std::net::IpAddr;

use netmon_common::{IPPROTO_TCP, IPPROTO_UDP};

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

/// What a filter can test, parsed once per packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fields {
    pub ethertype: u16,
    /// IP protocol, 0 for non-IP frames.
    pub proto: u8,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
}

/// The fields of an Ethernet frame (802.1Q and 802.1ad tags skipped).
pub fn fields(data: &[u8]) -> Fields {
    let mut f = Fields::default();
    let be16 = |i: usize| data.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let mut off = 12;
    let Some(mut et) = be16(off) else { return f };
    while et == 0x8100 || et == 0x88a8 {
        off += 4;
        let Some(next) = be16(off) else { return f };
        et = next;
    }
    f.ethertype = et;
    let l3 = off + 2;
    let l4 = match et {
        0x0800 => {
            let Some(b) = data.get(l3..l3 + 20) else { return f };
            let ihl = (b[0] & 0x0f) as usize * 4;
            f.proto = b[9];
            f.src = Some(IpAddr::from([b[12], b[13], b[14], b[15]]));
            f.dst = Some(IpAddr::from([b[16], b[17], b[18], b[19]]));
            // Later fragments carry no ports.
            let frag_off = u16::from_be_bytes([b[6], b[7]]) & 0x1fff;
            if frag_off != 0 {
                return f;
            }
            l3 + ihl
        }
        0x86dd => {
            let Some(b) = data.get(l3..l3 + 40) else { return f };
            f.proto = b[6];
            let a = |i: usize| -> [u8; 16] { b[i..i + 16].try_into().unwrap_or([0; 16]) };
            f.src = Some(IpAddr::from(a(8)));
            f.dst = Some(IpAddr::from(a(24)));
            l3 + 40
        }
        _ => return f,
    };
    if f.proto == IPPROTO_TCP || f.proto == IPPROTO_UDP {
        f.sport = be16(l4);
        f.dport = be16(l4 + 2);
    }
    f
}

#[derive(Clone, Debug, PartialEq)]
enum Dir {
    Any,
    Src,
    Dst,
}

#[derive(Clone, Debug, PartialEq)]
enum Term {
    Proto(u8),
    Ether(u16),
    Port(Dir, u16),
    Host(Dir, IpAddr),
    Net(IpAddr, u8),
    /// Protocol and port together (the shortcuts).
    ProtoPort(Option<u8>, u16),
    Not(Box<Term>),
}

/// A compiled filter: any group matches when all its terms match.
#[derive(Clone, Debug, PartialEq)]
pub struct Filter {
    groups: Vec<Vec<Term>>,
    text: String,
}

impl Filter {
    pub fn parse(text: &str) -> Result<Filter, String> {
        let words: Vec<String> = text.split_whitespace().map(str::to_ascii_lowercase).collect();
        if words.is_empty() {
            return Err("empty filter".into());
        }
        let mut groups = vec![Vec::new()];
        let mut i = 0;
        while i < words.len() {
            match words[i].as_str() {
                "and" | "&&" => i += 1,
                "or" | "||" => {
                    if groups.last().is_some_and(Vec::is_empty) {
                        return Err("\"or\" needs a term before it".into());
                    }
                    groups.push(Vec::new());
                    i += 1;
                }
                _ => {
                    let (t, used) = term(&words[i..])?;
                    groups.last_mut().expect("one group").push(t);
                    i += used;
                }
            }
        }
        if groups.iter().any(Vec::is_empty) {
            return Err("a filter cannot end with \"and\", \"or\" or \"not\"".into());
        }
        Ok(Filter { groups, text: words.join(" ") })
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn matches(&self, f: &Fields) -> bool {
        self.groups.iter().any(|g| g.iter().all(|t| term_matches(t, f)))
    }
}

/// One term from the start of `w`, and the number of words it used.
fn term(w: &[String]) -> Result<(Term, usize), String> {
    let num = |i: usize, what: &str| -> Result<u16, String> {
        w.get(i).and_then(|s| s.parse().ok()).ok_or_else(|| format!("\"{what}\" needs a port number"))
    };
    let ip = |i: usize| -> Result<IpAddr, String> {
        w.get(i).and_then(|s| s.parse().ok()).ok_or_else(|| "\"host\" needs an IP address".to_string())
    };
    let first = w[0].as_str();
    Ok(match first {
        "not" | "!" => {
            let (t, n) = term(w.get(1..).filter(|r| !r.is_empty()).ok_or("\"not\" needs a term after it")?)?;
            (Term::Not(Box::new(t)), n + 1)
        }
        "tcp" => (Term::Proto(IPPROTO_TCP), 1),
        "udp" => (Term::Proto(IPPROTO_UDP), 1),
        "icmp" => (Term::Proto(IPPROTO_ICMP), 1),
        "icmp6" => (Term::Proto(IPPROTO_ICMPV6), 1),
        "arp" => (Term::Ether(0x0806), 1),
        "ip" => (Term::Ether(0x0800), 1),
        "ip6" => (Term::Ether(0x86dd), 1),
        "dns" => (Term::ProtoPort(None, 53), 1),
        "http" => (Term::ProtoPort(Some(IPPROTO_TCP), 80), 1),
        "tls" | "https" => (Term::ProtoPort(Some(IPPROTO_TCP), 443), 1),
        "quic" => (Term::ProtoPort(Some(IPPROTO_UDP), 443), 1),
        "port" => (Term::Port(Dir::Any, num(1, "port")?), 2),
        "host" => (Term::Host(Dir::Any, ip(1)?), 2),
        "src" | "dst" => {
            let dir = if first == "src" { Dir::Src } else { Dir::Dst };
            match w.get(1).map(String::as_str) {
                Some("port") => (Term::Port(dir, num(2, "port")?), 3),
                Some("host") => (Term::Host(dir, ip(2)?), 3),
                // "src 1.2.3.4" is short for "src host 1.2.3.4".
                Some(s) if s.parse::<IpAddr>().is_ok() => (Term::Host(dir, ip(1)?), 2),
                _ => return Err(format!("\"{first}\" needs \"port N\" or \"host IP\"")),
            }
        }
        "net" => {
            let s = w.get(1).ok_or("\"net\" needs a network like 10.0.0.0/8")?;
            let (a, len) = s.split_once('/').unwrap_or((s, ""));
            let a: IpAddr = a.parse().map_err(|_| format!("net {s:?}: not a network"))?;
            let max = if a.is_ipv4() { 32 } else { 128 };
            let len = if len.is_empty() { max } else { len.parse().ok().filter(|l| *l <= max).ok_or(format!("net {s:?}: bad prefix"))? };
            (Term::Net(a, len), 2)
        }
        // A bare address or number: "1.1.1.1", "443".
        s if s.parse::<IpAddr>().is_ok() => (Term::Host(Dir::Any, ip(0)?), 1),
        s if s.parse::<u16>().is_ok() => (Term::Port(Dir::Any, num(0, "port")?), 1),
        s => return Err(format!("unknown word {s:?}: use tcp, udp, icmp, arp, ip, ip6, port N, host IP, net CIDR, dns, http, tls, quic, not, and, or")),
    })
}

fn term_matches(t: &Term, f: &Fields) -> bool {
    let port = |p: u16| f.sport == Some(p) || f.dport == Some(p);
    match t {
        Term::Proto(p) => f.proto == *p,
        Term::Ether(e) => f.ethertype == *e,
        Term::Port(Dir::Any, p) => port(*p),
        Term::Port(Dir::Src, p) => f.sport == Some(*p),
        Term::Port(Dir::Dst, p) => f.dport == Some(*p),
        Term::Host(Dir::Any, ip) => f.src == Some(*ip) || f.dst == Some(*ip),
        Term::Host(Dir::Src, ip) => f.src == Some(*ip),
        Term::Host(Dir::Dst, ip) => f.dst == Some(*ip),
        Term::Net(net, len) => [f.src, f.dst].into_iter().flatten().any(|a| in_net(a, *net, *len)),
        Term::ProtoPort(proto, p) => proto.is_none_or(|x| f.proto == x) && port(*p),
        Term::Not(t) => !term_matches(t, f),
    }
}

fn in_net(a: IpAddr, net: IpAddr, len: u8) -> bool {
    match (a, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => len == 0 || (u32::from(a) ^ u32::from(n)) >> (32 - len as u32) == 0,
        (IpAddr::V6(a), IpAddr::V6(n)) => len == 0 || (u128::from(a) ^ u128::from(n)) >> (128 - len as u32) == 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An Ethernet frame with IPv4 and TCP/UDP ports.
    fn v4(proto: u8, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut d = vec![0u8; 12];
        d.extend_from_slice(&[0x08, 0x00]);
        let mut ip = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, proto, 0, 0];
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        d.extend_from_slice(&ip);
        d.extend_from_slice(&sport.to_be_bytes());
        d.extend_from_slice(&dport.to_be_bytes());
        d.extend_from_slice(&[0; 16]);
        d
    }

    fn m(filter: &str, data: &[u8]) -> bool {
        Filter::parse(filter).unwrap().matches(&fields(data))
    }

    #[test]
    fn reads_ipv4_ipv6_and_vlan_fields() {
        let f = fields(&v4(IPPROTO_TCP, [10, 0, 0, 2], [1, 1, 1, 1], 50000, 443));
        assert_eq!((f.proto, f.sport, f.dport), (IPPROTO_TCP, Some(50000), Some(443)));
        assert_eq!(f.dst, Some("1.1.1.1".parse().unwrap()));
        let mut tagged = v4(IPPROTO_UDP, [10, 0, 0, 2], [8, 8, 8, 8], 40000, 53);
        tagged.splice(12..12, [0x81, 0x00, 0x00, 0x05]);
        assert_eq!(fields(&tagged).dport, Some(53), "VLAN tag skipped");
        let mut v6 = vec![0u8; 12];
        v6.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0, 0, 20, IPPROTO_UDP, 64]);
        v6.extend_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&"2606:4700::1111".parse::<std::net::Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&[0x9c, 0x40, 0x01, 0xbb]);
        let f = fields(&v6);
        assert_eq!((f.proto, f.dport, f.dst), (IPPROTO_UDP, Some(443), Some("2606:4700::1111".parse().unwrap())));
        assert_eq!(fields(&[0; 10]), Fields::default(), "short frame");
    }

    #[test]
    fn terms_combine_like_tcpdump() {
        let https = v4(IPPROTO_TCP, [10, 0, 0, 2], [1, 1, 1, 1], 50000, 443);
        let dns = v4(IPPROTO_UDP, [10, 0, 0, 2], [8, 8, 8, 8], 40000, 53);
        assert!(m("tcp port 443", &https) && !m("tcp port 443", &dns));
        assert!(m("tls", &https) && !m("quic", &https));
        assert!(m("dns", &dns) && m("udp and port 53", &dns));
        assert!(m("dst port 443", &https) && !m("src port 443", &https));
        assert!(m("host 1.1.1.1", &https) && m("dst 1.1.1.1", &https) && !m("src host 1.1.1.1", &https));
        assert!(m("net 10.0.0.0/8", &dns) && !m("net 192.168.0.0/16", &dns));
        assert!(m("not tcp", &dns) && !m("not tcp", &https));
        assert!(m("dns or tls", &https) && m("dns or tls", &dns));
        assert!(m("tcp and port 443 or port 53", &dns), "and binds first");
        assert!(m("1.1.1.1", &https) && m("443", &https));
        assert!(!m("icmp", &https) && !m("arp", &https) && m("ip", &https) && !m("ip6", &https));
        assert_eq!(Filter::parse("  TCP   Port 443 ").unwrap().text(), "tcp port 443");
    }

    #[test]
    fn bad_filters_explain_themselves() {
        for (f, want) in [
            ("", "empty"),
            ("port", "port number"),
            ("host foo", "IP address"),
            ("tcp or", "cannot end"),
            ("or tcp", "term before"),
            ("not", "needs a term after it"),
            ("src 443", "needs \"port N\""),
            ("net 10.0.0.0/40", "bad prefix"),
            ("tpc", "unknown word"),
        ] {
            let e = Filter::parse(f).unwrap_err();
            assert!(e.contains(want), "{f:?}: {e}");
        }
    }
}
