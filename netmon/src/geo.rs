//! Country and network owner (AS) of remote addresses, from the DB-IP Lite
//! databases (CC BY 4.0, IP Geolocation by DB-IP, https://db-ip.com).
//! The UI looks the addresses up; netmond does not need the files.

use std::{
    cell::RefCell,
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
};

use maxminddb::Reader;

/// Directory of the database files.
pub const DEFAULT_DIR: &str = "/var/lib/netmon";
pub const COUNTRY_FILE: &str = "dbip-country-lite.mmdb";
pub const ASN_FILE: &str = "dbip-asn-lite.mmdb";
/// Addresses cached at most; then the cache starts again.
const MAX_CACHE: usize = 20_000;
/// Longest organization name shown.
const MAX_ORG: usize = 28;

#[derive(serde::Deserialize)]
struct CountryRecord {
    country: Option<IsoCode>,
}

#[derive(serde::Deserialize)]
struct IsoCode {
    iso_code: Option<String>,
}

#[derive(serde::Deserialize)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

#[derive(Default)]
pub struct Geo {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
    cache: RefCell<HashMap<IpAddr, String>>,
    /// Why a file could not be read, empty if both were read.
    pub error: String,
}

impl Geo {
    /// Opens the database files in `dir`. A missing file is no error: its
    /// part stays empty.
    pub fn open(dir: &Path) -> Self {
        let mut g = Geo::default();
        let mut errors = Vec::new();
        let mut open = |file: &str| -> Option<Reader<Vec<u8>>> {
            let p: PathBuf = dir.join(file);
            match Reader::open_readfile(&p) {
                Ok(r) => Some(r),
                Err(_) if !p.exists() => None,
                Err(e) => {
                    errors.push(format!("{}: {e}", p.display()));
                    None
                }
            }
        };
        g.country = open(COUNTRY_FILE);
        g.asn = open(ASN_FILE);
        g.error = errors.join("; ");
        g
    }

    /// Is any database loaded?
    pub fn loaded(&self) -> bool {
        self.country.is_some() || self.asn.is_some()
    }

    /// The ISO country code of a public address, if the country database
    /// knows it.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        if !is_public(ip) {
            return None;
        }
        let c = self.country.as_ref()?.lookup(ip).ok()?.decode::<CountryRecord>().ok()??;
        c.country?.iso_code.filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
    }

    /// "DE AS3320 Deutsche Telekom AG" for a public address; empty for a
    /// private one or when nothing is known.
    pub fn label(&self, ip: IpAddr) -> String {
        if !self.loaded() || !is_public(ip) {
            return String::new();
        }
        if let Some(l) = self.cache.borrow().get(&ip) {
            return l.clone();
        }
        let country = self
            .country
            .as_ref()
            .and_then(|r| r.lookup(ip).ok()?.decode::<CountryRecord>().ok()?)
            .and_then(|c| c.country?.iso_code);
        let asn = self.asn.as_ref().and_then(|r| r.lookup(ip).ok()?.decode::<AsnRecord>().ok()?);
        let l = label(
            country.as_deref(),
            asn.as_ref().and_then(|a| a.autonomous_system_number),
            asn.as_ref().and_then(|a| a.autonomous_system_organization.as_deref()),
        );
        let mut cache = self.cache.borrow_mut();
        if cache.len() >= MAX_CACHE {
            cache.clear();
        }
        cache.insert(ip, l.clone());
        l
    }
}

/// Joins the known parts; the organization is cut to MAX_ORG characters
/// and stripped of control characters.
pub fn label(country: Option<&str>, asn: Option<u32>, org: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(c) = country.filter(|c| !c.is_empty()) {
        parts.push(crate::text::sanitize(c));
    }
    if let Some(n) = asn {
        parts.push(format!("AS{n}"));
    }
    if let Some(o) = org.filter(|o| !o.is_empty()) {
        let o = crate::text::sanitize(o);
        let mut cut: String = o.chars().take(MAX_ORG).collect();
        if o.chars().count() > MAX_ORG {
            cut.push('…');
        }
        parts.push(cut);
    }
    parts.join(" ")
}

/// Addresses that a public database can know: not private, loopback,
/// link-local, multicast, CGNAT or documentation ranges.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || (o[0] == 100 && (64..128).contains(&o[1])))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_join_known_parts() {
        assert_eq!(label(Some("DE"), Some(3320), Some("Deutsche Telekom AG")), "DE AS3320 Deutsche Telekom AG");
        assert_eq!(label(None, Some(13335), None), "AS13335");
        assert_eq!(label(Some("US"), None, Some("A very long organization name, Inc.")), "US A very long organization nam…");
        assert_eq!(label(None, None, Some("\x1b[31mred")), "?[31mred", "no control characters");
        assert_eq!(label(None, None, None), "");
    }

    /// Runs against real DB-IP Lite files when NETMON_GEO_TEST_DIR names
    /// their directory; else it does nothing.
    #[test]
    fn real_databases_when_present() {
        let Some(dir) = std::env::var_os("NETMON_GEO_TEST_DIR") else { return };
        let g = Geo::open(Path::new(&dir));
        assert!(g.loaded() && g.error.is_empty(), "{}", g.error);
        let l = g.label("1.1.1.1".parse().unwrap());
        assert!(l.contains("AS13335"), "{l}");
        let l = g.label("2a00:1450:4001:80b::200e".parse().unwrap());
        assert!(l.contains("AS15169"), "{l}");
        assert_eq!(g.label("192.168.1.1".parse().unwrap()), "");
        eprintln!("1.1.1.1 -> {}", g.label("1.1.1.1".parse().unwrap()));
        eprintln!("8.8.8.8 -> {}", g.label("8.8.8.8".parse().unwrap()));
        eprintln!("193.99.144.80 -> {}", g.label("193.99.144.80".parse().unwrap()));
    }

    #[test]
    fn only_public_addresses_are_looked_up() {
        for ip in ["10.1.2.3", "192.168.1.1", "100.95.0.251", "127.0.0.1", "169.254.1.1", "224.0.0.251", "fe80::1", "fd00::1", "::1", "2001:db8::1", "::ffff:10.0.0.1"] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        let g = Geo::open(Path::new("/nonexistent"));
        assert!(!g.loaded() && g.error.is_empty(), "missing files are no error");
        assert_eq!(g.label("1.1.1.1".parse().unwrap()), "");
    }
}
