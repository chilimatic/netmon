//! Alerts: a program above a rate for some seconds, or a program that
//! connects to a country it never used before. Configured by `[alerts]` in
//! the rules file; off by default. The messages go to the journal, the UI
//! status line and netmon-notify.

use std::path::PathBuf;

use super::*;
use crate::usage::{UNKNOWN, program};

/// One rate alert per program at most in this time.
const RATE_REPEAT: Duration = Duration::from_secs(600);
/// Without a countries file, the first minutes only learn: a browser
/// reaches dozens of countries at its first start.
const LEARN: Duration = Duration::from_secs(600);
/// Country alerts per tick at most.
const MAX_PER_TICK: usize = 5;
/// (program, country) pairs remembered at most.
const MAX_SEEN: usize = 100_000;
/// How often the countries file is written while it changes.
const SAVE_EVERY: Duration = Duration::from_secs(60);
pub(crate) const COUNTRIES_PATH: &str = "/var/lib/netmon/countries.json";

#[derive(Default)]
pub(crate) struct Alerts {
    /// Seconds each program has been above the rate.
    above: HashMap<String, f64>,
    last_rate: HashMap<String, Instant>,
    /// Opened at the first tick with `new_country`; None inside: no file.
    geo: Option<Option<crate::geo::Geo>>,
    seen: HashSet<(String, String)>,
    /// Flows already looked at.
    checked: HashSet<netmon_common::FlowKey>,
    learn_until: Option<Instant>,
    /// Where `seen` is kept (daemon only), and the group of the file.
    pub(crate) path: Option<PathBuf>,
    pub(crate) gid: Option<u32>,
    /// Directory of the DB-IP files; None: crate::geo::DEFAULT_DIR.
    pub(crate) geo_dir: Option<PathBuf>,
    loaded: bool,
    dirty: bool,
    saved: Option<Instant>,
}

impl Alerts {
    /// The alerts of this tick. `dt`: seconds since the last tick.
    pub(crate) fn check(
        &mut self,
        cfg: &rules::AlertConfig,
        flows: &HashMap<netmon_common::FlowKey, crate::collector::Flow>,
        counted: &HashSet<u32>,
        dt: f64,
        now: Instant,
    ) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(limit) = cfg.rate_mb {
            self.rates(limit, cfg.rate_seconds(), flows, counted, dt, now, &mut out);
        } else {
            self.above.clear();
        }
        if cfg.new_country {
            self.countries(flows, now, &mut out);
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn rates(
        &mut self,
        limit_mb: f64,
        secs: u32,
        flows: &HashMap<netmon_common::FlowKey, crate::collector::Flow>,
        counted: &HashSet<u32>,
        dt: f64,
        now: Instant,
        out: &mut Vec<String>,
    ) {
        let mut rate: HashMap<String, f64> = HashMap::new();
        for (k, f) in flows {
            let counts = if counted.is_empty() { k.ifindex != 1 } else { counted.contains(&k.ifindex) };
            if counts {
                *rate.entry(program(f)).or_default() += f.tx_rate + f.rx_rate;
            }
        }
        let limit = limit_mb * 1e6;
        self.above.retain(|p, _| rate.get(p).is_some_and(|r| *r >= limit));
        for (p, r) in rate.into_iter().filter(|(_, r)| *r >= limit) {
            let t = self.above.entry(p.clone()).or_default();
            *t += dt;
            if *t >= secs as f64 && self.last_rate.get(&p).is_none_or(|l| now.duration_since(*l) >= RATE_REPEAT) {
                self.last_rate.insert(p.clone(), now);
                out.push(format!("{p} uses {:.1} MB/s for {secs} s (limit {limit_mb} MB/s)", r / 1e6));
            }
        }
    }

    fn countries(&mut self, flows: &HashMap<netmon_common::FlowKey, crate::collector::Flow>, now: Instant, out: &mut Vec<String>) {
        if self.geo.is_none() {
            let dir = self.geo_dir.clone().unwrap_or_else(|| crate::geo::DEFAULT_DIR.into());
            let g = crate::geo::Geo::open(&dir);
            self.geo = Some(g.loaded().then_some(g));
        }
        if !self.loaded {
            self.loaded = true;
            match self.path.as_deref().map(std::fs::read_to_string) {
                Some(Ok(text)) => {
                    let pairs: Vec<(String, String)> = serde_json::from_str(&text).unwrap_or_default();
                    self.seen.extend(pairs);
                }
                _ => self.learn_until = Some(now + LEARN),
            }
        }
        let Some(Some(geo)) = &self.geo else { return };
        let learning = self.learn_until.is_some_and(|t| now < t);
        let mut sent = 0;
        for (k, f) in flows {
            if !self.checked.insert(*k) {
                continue;
            }
            let p = program(f);
            if p == UNKNOWN {
                continue;
            }
            let ip = crate::procmap::normalize(crate::collector::addr(k.family, &k.remote_addr, 0)).ip();
            let Some(c) = geo.country(ip) else { continue };
            if self.seen.len() >= MAX_SEEN || !self.seen.insert((p.clone(), c.clone())) {
                continue;
            }
            self.dirty = true;
            if learning || sent >= MAX_PER_TICK {
                continue;
            }
            sent += 1;
            let host = f.host.as_deref().map(|h| format!(" ({h})")).unwrap_or_default();
            out.push(format!("{p} connects to {c} for the first time: {ip}{host}"));
        }
        self.checked.retain(|k| flows.contains_key(k));
    }

    /// Writes the countries file if it changed and a minute passed (or
    /// `force`). Returns an error message.
    pub(crate) fn save(&mut self, now: Instant, force: bool) -> Option<String> {
        let path = self.path.clone()?;
        if !self.dirty || (!force && self.saved.is_some_and(|s| now.duration_since(s) < SAVE_EVERY)) {
            return None;
        }
        self.saved = Some(now);
        let mut pairs: Vec<&(String, String)> = self.seen.iter().collect();
        pairs.sort();
        let text = serde_json::to_string(&pairs).unwrap_or_default();
        match crate::usage::write_private(&path, text.as_bytes(), self.gid) {
            Ok(()) => {
                self.dirty = false;
                None
            }
            Err(e) => Some(format!("countries file {}: {e}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::Collector;
    use crate::procmap::{Owner, ProcDetails};
    use netmon_common::{FlowKey, FlowStats};

    fn flow(c: &mut Collector, remote: [u8; 4], exe: &str, bytes: u64) -> FlowKey {
        let mut k = FlowKey { family: 4, proto: 6, local_port: 40000, remote_port: 443, ifindex: 2, ..Default::default() };
        k.remote_addr[..4].copy_from_slice(&remote);
        c.ingest([(k, FlowStats { rx_bytes: bytes, ..Default::default() })], 1.0);
        let f = c.flows.get_mut(&k).unwrap();
        f.owner = Some(Owner {
            pid: 7,
            comm: "app".into(),
            uid: Some(0),
            details: Some(ProcDetails { exe: exe.into(), ..ProcDetails::default() }),
            container: None,
        });
        k
    }

    #[test]
    fn rate_alert_after_the_seconds_and_not_again_soon() {
        let cfg = rules::AlertConfig { rate_mb: Some(10.0), rate_seconds: 3, new_country: false, new_device: false };
        let mut a = Alerts::default();
        let mut c = Collector::new(30);
        let t0 = Instant::now();
        let counted = HashSet::new();
        let mut got = Vec::new();
        for s in 1..=5u64 {
            flow(&mut c, [1, 1, 1, 1], "/usr/bin/big", s * 20_000_000);
            got.push(a.check(&cfg, &c.flows, &counted, 1.0, t0 + Duration::from_secs(s)));
        }
        assert!(got[0].is_empty() && got[1].is_empty(), "{got:?}");
        assert_eq!(got[2], ["/usr/bin/big uses 20.0 MB/s for 3 s (limit 10 MB/s)"], "{got:?}");
        assert!(got[3].is_empty() && got[4].is_empty(), "once per 10 minutes");
    }

    #[test]
    fn new_country_alerts_after_learning_and_remembers_pairs() {
        let Some(dir) = std::env::var_os("NETMON_GEO_TEST_DIR") else { return };
        let d = {
            let _fs = crate::test_fs_lock();
            let d = std::env::temp_dir().join(format!("netmon-alerts-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        };
        let path = d.join("countries.json");
        let cfg = rules::AlertConfig { rate_mb: None, rate_seconds: 0, new_country: true, new_device: false };
        let mut a = Alerts { path: Some(path.clone()), geo_dir: Some(dir.into()), ..Alerts::default() };
        let t0 = Instant::now();
        let mut c = Collector::new(30);
        flow(&mut c, [8, 8, 8, 8], "/usr/bin/curl", 10);
        assert!(a.check(&cfg, &c.flows, &HashSet::new(), 1.0, t0).is_empty(), "no file yet: learning");
        assert!(a.save(t0, true).is_none());
        assert!(std::fs::read_to_string(&path).unwrap().contains("[\"/usr/bin/curl\",\"US\"]"));
        // A new netmond with the file: no learning; a new country alerts once.
        let mut b = Alerts { path: Some(path.clone()), geo_dir: a.geo_dir.clone(), ..Alerts::default() };
        let mut c = Collector::new(30);
        flow(&mut c, [8, 8, 8, 8], "/usr/bin/curl", 10);
        flow(&mut c, [193, 99, 144, 80], "/usr/bin/curl", 10);
        let got = b.check(&cfg, &c.flows, &HashSet::new(), 1.0, t0);
        assert_eq!(got, ["/usr/bin/curl connects to DE for the first time: 193.99.144.80"], "{got:?}");
        assert!(b.check(&cfg, &c.flows, &HashSet::new(), 1.0, t0).is_empty(), "the same flows are not checked again");
        let _ = std::fs::remove_dir_all(&d);
    }
}
