//! Traffic per program and day. `netmond` adds the bytes of each flow to
//! its program (exe path, else process name) for the local date, and keeps
//! 90 days in `/var/lib/netmon/usage.json` (root, group `netmon`, 0640).
//! The UI reads the file (Usage tab).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Write as _,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use netmon_common::FlowKey;

use crate::collector::Flow;

pub const DEFAULT_PATH: &str = "/var/lib/netmon/usage.json";
/// Days kept in the file.
const KEEP_DAYS: usize = 90;
/// Programs per day at most; the rest add up in OTHER.
const MAX_PROGRAMS: usize = 2000;
const OTHER: &str = "(other programs)";
pub(crate) const UNKNOWN: &str = "(unknown)";
/// How often `netmond` writes the file.
pub const SAVE_EVERY: Duration = Duration::from_secs(60);
const LOOPBACK_IFINDEX: u32 = 1;

/// Date (YYYY-MM-DD) -> program -> [bytes up, bytes down].
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UsageFile {
    pub days: BTreeMap<String, BTreeMap<String, [u64; 2]>>,
}

/// One program in the Usage tab: [up, down] per time window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsageRow {
    pub program: String,
    pub today: [u64; 2],
    pub yesterday: [u64; 2],
    /// Today and the 6 days before.
    pub week: [u64; 2],
    /// Today and the 29 days before.
    pub month: [u64; 2],
}

impl UsageFile {
    pub fn add(&mut self, day: &str, program: &str, up: u64, down: u64) {
        let progs = self.days.entry(day.to_string()).or_default();
        let key = if progs.contains_key(program) || progs.len() < MAX_PROGRAMS { program } else { OTHER };
        let v = progs.entry(key.to_string()).or_default();
        v[0] += up;
        v[1] += down;
    }

    /// Drops all but the newest KEEP_DAYS days.
    pub fn prune(&mut self) {
        while self.days.len() > KEEP_DAYS {
            self.days.pop_first();
        }
    }

    /// The programs with their windows up to `today`, the busiest today
    /// first, then by the last 7 days.
    pub fn rows(&self, today: &str) -> Vec<UsageRow> {
        let Some(t) = day_number(today) else { return Vec::new() };
        let mut rows: HashMap<&str, UsageRow> = HashMap::new();
        for (day, progs) in &self.days {
            let Some(d) = day_number(day) else { continue };
            let age = t - d;
            if !(0..30).contains(&age) {
                continue;
            }
            for (p, v) in progs {
                let r = rows.entry(p).or_insert_with(|| UsageRow { program: p.clone(), ..UsageRow::default() });
                let add = |w: &mut [u64; 2]| {
                    w[0] += v[0];
                    w[1] += v[1];
                };
                add(&mut r.month);
                if age < 7 {
                    add(&mut r.week);
                }
                if age == 1 {
                    add(&mut r.yesterday);
                }
                if age == 0 {
                    add(&mut r.today);
                }
            }
        }
        let mut out: Vec<UsageRow> = rows.into_values().collect();
        out.sort_by(|a, b| {
            let sum = |w: [u64; 2]| w[0] + w[1];
            sum(b.today).cmp(&sum(a.today)).then(sum(b.week).cmp(&sum(a.week))).then(a.program.cmp(&b.program))
        });
        out
    }
}

/// Days since 1970 of "YYYY-MM-DD".
fn day_number(s: &str) -> Option<i64> {
    let mut it = s.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (y, m, d) = (it.next()??, it.next()??, it.next()??);
    Some(crate::rulefile::days_from_civil(y, m, d))
}

/// Today's local date as YYYY-MM-DD.
pub fn today() -> String {
    let now = crate::rules::unix_now() as libc::time_t;
    // SAFETY: localtime_r writes only into `tm`; both pointers are valid.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&now, &mut tm) }.is_null() {
        return crate::rulefile::utc(now as u64)[..10].to_string();
    }
    format!("{:04}-{:02}-{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday)
}

/// Reads the file. A missing file is an empty one.
pub fn load(path: &Path) -> Result<UsageFile, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UsageFile::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The counter in `netmond`.
pub struct Usage {
    pub file: UsageFile,
    path: PathBuf,
    gid: Option<u32>,
    /// Totals of each flow at the last count.
    last: HashMap<FlowKey, (u64, u64)>,
    saved: Instant,
    dirty: bool,
    /// The last save failed: the next error is not reported again.
    failing: bool,
}

impl Usage {
    /// Starts from the file at `path`. A file that cannot be read is
    /// reported and replaced at the next save.
    pub fn new(path: &Path, gid: Option<u32>) -> (Self, Option<String>) {
        let (file, err) = match load(path) {
            Ok(f) => (f, None),
            Err(e) => (UsageFile::default(), Some(format!("usage file: {e}; starting empty"))),
        };
        let u = Usage { file, path: path.to_path_buf(), gid, last: HashMap::new(), saved: Instant::now(), dirty: false, failing: false };
        (u, err)
    }

    /// Adds the bytes since the last count. Only flows on `counted`
    /// interfaces (empty: all but loopback), so traffic that passes a
    /// bridge, a veth and the uplink counts once.
    pub fn count(&mut self, flows: &HashMap<FlowKey, Flow>, counted: &HashSet<u32>, day: &str) {
        let mut seen = HashMap::with_capacity(flows.len());
        for (k, f) in flows {
            let counts = if counted.is_empty() { k.ifindex != LOOPBACK_IFINDEX } else { counted.contains(&k.ifindex) };
            if !counts {
                continue;
            }
            let now = (f.total.tx_bytes, f.total.rx_bytes);
            let before = self.last.get(k).copied().unwrap_or((0, 0));
            // A smaller total: the kernel entry was new (LRU eviction).
            let (up, down) = if now.0 < before.0 || now.1 < before.1 { now } else { (now.0 - before.0, now.1 - before.1) };
            seen.insert(*k, now);
            if up + down > 0 {
                self.file.add(day, &program(f), up, down);
                self.dirty = true;
            }
        }
        self.last = seen;
    }

    /// Writes the file if it changed and SAVE_EVERY passed (or `force`).
    /// Returns an error message the first time writing fails.
    pub fn save(&mut self, now: Instant, force: bool) -> Option<String> {
        if !self.dirty || (!force && now.duration_since(self.saved) < SAVE_EVERY) {
            return None;
        }
        self.saved = now;
        self.file.prune();
        match self.write() {
            Ok(()) => {
                self.dirty = false;
                self.failing = false;
                None
            }
            Err(e) => {
                let first = !self.failing;
                self.failing = true;
                first.then(|| format!("usage file {}: {e}", self.path.display()))
            }
        }
    }

    fn write(&self) -> std::io::Result<()> {
        write_private(&self.path, serde_json::to_string(&self.file).unwrap_or_default().as_bytes(), self.gid)
    }
}

/// Writes `data` to `path` through a temporary file and rename, mode 0640,
/// group `gid`: readers never see half a file.
pub(crate) fn write_private(path: &Path, data: &[u8], gid: Option<u32>) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o640).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
    if let Some(gid) = gid {
        std::os::unix::fs::fchown(&f, None, Some(gid))?;
    }
    f.set_permissions(std::fs::Permissions::from_mode(0o640))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// The program a flow counts for.
pub(crate) fn program(f: &Flow) -> String {
    let Some(o) = &f.owner else { return UNKNOWN.into() };
    let exe = o.details.as_ref().map(|d| d.exe.as_str()).filter(|e| !e.is_empty());
    match (&o.container, exe) {
        (Some(c), _) => format!("container:{c}/{}", o.comm),
        (None, Some(e)) => e.to_string(),
        (None, None) if o.comm.is_empty() => UNKNOWN.into(),
        (None, None) => o.comm.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::Collector;
    use netmon_common::FlowStats;

    #[test]
    fn windows_add_up_by_age() {
        let mut f = UsageFile::default();
        f.add("2026-11-23", "/usr/bin/curl", 10, 100);
        f.add("2026-11-22", "/usr/bin/curl", 1, 2);
        f.add("2026-11-17", "/usr/bin/curl", 1000, 0);
        f.add("2026-11-16", "/usr/bin/curl", 5, 5);
        f.add("2026-10-01", "/usr/bin/curl", 7, 7);
        f.add("2026-11-23", "/usr/bin/firefox", 1, 1);
        let rows = f.rows("2026-11-23");
        assert_eq!(rows[0].program, "/usr/bin/curl", "busiest today first");
        assert_eq!(rows[0].today, [10, 100]);
        assert_eq!(rows[0].yesterday, [1, 2]);
        assert_eq!(rows[0].week, [1011, 102], "today and the 6 days before");
        assert_eq!(rows[0].month, [1016, 107], "not October");
        assert_eq!(rows[1].today, [1, 1]);
    }

    #[test]
    fn programs_per_day_and_days_are_limited() {
        let mut f = UsageFile::default();
        for i in 0..MAX_PROGRAMS + 5 {
            f.add("2026-11-23", &format!("/p{i}"), 1, 0);
        }
        f.add("2026-11-23", "/p0", 1, 0);
        let day = &f.days["2026-11-23"];
        assert_eq!(day.len(), MAX_PROGRAMS + 1);
        assert_eq!((day["/p0"], day[OTHER]), ([2, 0], [5, 0]));
        for d in 1..=28 {
            for m in 1..=4 {
                f.add(&format!("2026-{m:02}-{d:02}"), "/x", 1, 1);
            }
        }
        f.prune();
        assert_eq!(f.days.len(), KEEP_DAYS);
        assert!(f.days.contains_key("2026-11-23"), "the newest stay");
    }

    #[test]
    fn counts_deltas_on_counted_interfaces_and_saves() {
        let dir = {
            let _fs = crate::test_fs_lock();
            let d = std::env::temp_dir().join(format!("netmon-usage-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        };
        let path = dir.join("usage.json");
        let (mut u, err) = Usage::new(&path, None);
        assert!(err.is_none());
        let mut c = Collector::new(30);
        let k = |ifindex| FlowKey { family: 4, proto: 6, local_port: 1, remote_port: 443, ifindex, ..Default::default() };
        c.ingest([(k(2), FlowStats { tx_bytes: 100, rx_bytes: 1000, ..Default::default() })], 1.0);
        c.ingest([(k(9), FlowStats { tx_bytes: 50, rx_bytes: 50, ..Default::default() })], 1.0);
        let counted = HashSet::from([2]);
        u.count(&c.flows, &counted, "2026-11-23");
        c.ingest([(k(2), FlowStats { tx_bytes: 150, rx_bytes: 3000, ..Default::default() })], 1.0);
        u.count(&c.flows, &counted, "2026-11-23");
        assert_eq!(u.file.days["2026-11-23"][UNKNOWN], [150, 3000], "deltas, only interface 2");
        assert!(u.save(Instant::now(), false).is_none() && !path.exists(), "not due yet");
        assert!(u.save(Instant::now(), true).is_none());
        assert_eq!(load(&path).unwrap(), u.file);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);
        let (again, _) = Usage::new(&path, None);
        assert_eq!(again.file, u.file, "a restart goes on from the file");
        std::fs::write(&path, "not json").unwrap();
        assert!(Usage::new(&path, None).1.unwrap().contains("starting empty"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
