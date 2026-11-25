//! The DNS log: every DNS answer the host receives, with the program that
//! asked. The monitor keeps the newest entries in memory and sends new ones
//! to the UIs. Encrypted DNS (DNS over HTTPS or TLS) is not seen.

use std::net::IpAddr;

/// Entries the monitor and each UI keep.
pub const MAX_ENTRIES: usize = 5_000;

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DnsEntry {
    /// Unix seconds.
    pub time: u64,
    /// The exe, `container:<name>/<process>`, or `(unknown)`. With a local
    /// stub resolver, programs ask the stub and the stub asks upstream:
    /// both show.
    pub program: String,
    pub pid: Option<u32>,
    /// The DNS server that answered.
    pub server: IpAddr,
    pub name: String,
    /// "A", "AAAA", "HTTPS", ...
    pub qtype: String,
    /// "ok", "NXDOMAIN", "SERVFAIL", ...
    pub rcode: String,
    /// Addresses and CNAME targets.
    pub answers: Vec<String>,
    /// A host block or block list matches the name.
    pub blocked: bool,
}

impl DnsEntry {
    /// What the Result column shows.
    pub fn result(&self) -> String {
        if self.rcode != "ok" {
            self.rcode.clone()
        } else if self.answers.is_empty() {
            "no address".into()
        } else {
            self.answers.join(" ")
        }
    }
}
