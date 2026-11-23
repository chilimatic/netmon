//! The connection log: one JSON line per new connection of a program to a
//! destination, and per denied outbound connection. `netmond` writes it;
//! the UI reads it (Log tab). The file belongs to root, group `netmon`,
//! mode 0640: the log shows which programs talk to which hosts.

use std::{
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    net::IpAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const DEFAULT_PATH: &str = "/var/log/netmon/connections.log";
/// At this size the file moves to `<path>.1` (the old `.1` goes).
const MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Remembered (program, destination) pairs at most; then the set starts
/// again, and pairs are logged again once.
const MAX_SEEN: usize = 65_536;
/// A denied destination of a program is logged at most once in this time:
/// programs retry denied connections in a loop.
const DENY_REPEAT: Duration = Duration::from_secs(60);
/// Bytes read from the end of the file for the Log tab.
const TAIL_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    /// UTC, like 2026-11-23T14:08:08Z.
    pub time: String,
    /// "new" or "denied".
    pub event: String,
    /// "out", "in", or empty if unknown.
    pub dir: String,
    pub proto: String,
    pub remote: IpAddr,
    pub port: u16,
    /// Hostname of the remote address, empty if unknown.
    pub host: String,
    /// 0 if unknown.
    pub pid: u32,
    pub comm: String,
    /// Empty if unknown.
    pub exe: String,
}

impl Entry {
    /// The program, for de-duplication: the exe, else the process name.
    fn program(&self) -> &str {
        if self.exe.is_empty() { &self.comm } else { &self.exe }
    }
}

type SeenKey = (String, IpAddr, u16, String, String);

pub struct ConnLog {
    path: PathBuf,
    /// Group of a new file.
    gid: Option<u32>,
    file: Option<File>,
    size: u64,
    seen: HashSet<SeenKey>,
    denied: HashMap<SeenKey, Instant>,
    /// The last write failed: the next error is not reported again.
    failing: bool,
}

impl ConnLog {
    pub fn new(path: &Path, gid: Option<u32>) -> Self {
        ConnLog {
            path: path.to_path_buf(),
            gid,
            file: None,
            size: 0,
            seen: HashSet::new(),
            denied: HashMap::new(),
            failing: false,
        }
    }

    /// Logs a connection, once per program and destination. Returns an
    /// error message the first time writing fails.
    pub fn new_conn(&mut self, e: &Entry) -> Option<String> {
        if self.seen.len() >= MAX_SEEN {
            self.seen.clear();
        }
        let key = (e.program().to_string(), e.remote, e.port, e.proto.clone(), e.dir.clone());
        if !self.seen.insert(key) {
            return None;
        }
        self.write(e)
    }

    /// Logs a denied connection, at most once per program, destination
    /// and minute.
    pub fn denied(&mut self, e: &Entry, now: Instant) -> Option<String> {
        if self.denied.len() >= MAX_SEEN {
            self.denied.retain(|_, t| now.duration_since(*t) < DENY_REPEAT);
        }
        let key = (e.program().to_string(), e.remote, e.port, e.proto.clone(), e.dir.clone());
        if self.denied.get(&key).is_some_and(|t| now.duration_since(*t) < DENY_REPEAT) {
            return None;
        }
        self.denied.insert(key, now);
        self.write(e)
    }

    fn write(&mut self, e: &Entry) -> Option<String> {
        let line = crate::proto::line(e);
        match self.append(line.as_bytes()) {
            Ok(()) => {
                self.failing = false;
                None
            }
            Err(err) => {
                self.file = None;
                let first = !self.failing;
                self.failing = true;
                first.then(|| format!("connection log {}: {err}", self.path.display()))
            }
        }
    }

    fn append(&mut self, line: &[u8]) -> std::io::Result<()> {
        if self.file.is_some() && self.size + line.len() as u64 > MAX_BYTES {
            self.file = None;
            let mut old = self.path.clone().into_os_string();
            old.push(".1");
            std::fs::rename(&self.path, old)?;
        }
        if self.file.is_none() {
            self.open()?;
        }
        let f = self.file.as_mut().ok_or_else(|| std::io::Error::other("not open"))?;
        f.write_all(line)?;
        self.size += line.len() as u64;
        Ok(())
    }

    fn open(&mut self) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let f = OpenOptions::new().create(true).append(true).mode(0o640).custom_flags(libc::O_NOFOLLOW).open(&self.path)?;
        let meta = f.metadata()?;
        // The group may read; nobody else. Also for a file made by hand.
        if let Some(gid) = self.gid {
            std::os::unix::fs::fchown(&f, None, Some(gid))?;
        }
        f.set_permissions(std::fs::Permissions::from_mode(0o640))?;
        self.size = meta.len();
        self.file = Some(f);
        Ok(())
    }
}

/// The newest entries of the log at `path`, newest first, at most `max`.
/// Reads the end of the file only; lines that do not parse are skipped.
pub fn tail(path: &Path, max: usize) -> Result<Vec<Entry>, String> {
    let mut f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let len = f.metadata().map_err(|e| e.to_string())?.len();
    let start = len.saturating_sub(TAIL_BYTES);
    f.seek(SeekFrom::Start(start)).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<&str> = text.lines().collect();
    // The first line can be cut in the middle.
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    Ok(lines.iter().rev().filter_map(|l| serde_json::from_str(l).ok()).take(max).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(event: &str, exe: &str, port: u16) -> Entry {
        Entry {
            time: "2026-11-23T14:08:08Z".into(),
            event: event.into(),
            dir: "out".into(),
            proto: "tcp".into(),
            remote: "1.1.1.1".parse().unwrap(),
            port,
            host: "one.one.one.one".into(),
            pid: 7,
            comm: "curl".into(),
            exe: exe.into(),
        }
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("netmon-log-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn logs_once_per_program_and_destination() {
        let d = dir("once");
        let path = d.join("sub/connections.log");
        let mut log = ConnLog::new(&path, None);
        assert_eq!(log.new_conn(&entry("new", "/usr/bin/curl", 443)), None);
        assert_eq!(log.new_conn(&entry("new", "/usr/bin/curl", 443)), None);
        log.new_conn(&entry("new", "/usr/bin/curl", 80));
        let t0 = Instant::now();
        log.denied(&entry("denied", "/usr/bin/curl", 25), t0);
        log.denied(&entry("denied", "/usr/bin/curl", 25), t0 + Duration::from_secs(30));
        log.denied(&entry("denied", "/usr/bin/curl", 25), t0 + Duration::from_secs(61));
        let got: Vec<_> = tail(&path, 10).unwrap().into_iter().map(|e| (e.event, e.port)).collect();
        assert_eq!(got, vec![("denied".into(), 25), ("denied".into(), 25), ("new".into(), 80), ("new".into(), 443)]);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rotates_and_reports_errors_once() {
        let d = dir("rotate");
        let path = d.join("connections.log");
        let mut log = ConnLog::new(&path, None);
        log.new_conn(&entry("new", "/a", 1));
        log.size = MAX_BYTES;
        log.new_conn(&entry("new", "/a", 2));
        assert_eq!(tail(&path, 10).unwrap().len(), 1, "new file after rotation");
        assert_eq!(tail(&d.join("connections.log.1"), 10).unwrap()[0].port, 1);
        // A directory in the way: the first failure is reported, later ones not.
        let mut bad = ConnLog::new(&d, None);
        assert!(bad.new_conn(&entry("new", "/a", 3)).is_some());
        assert!(bad.new_conn(&entry("new", "/a", 4)).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tail_skips_a_cut_first_line() {
        let d = dir("tail");
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join("connections.log");
        let line = crate::proto::line(&entry("new", "/a", 1));
        let n = (TAIL_BYTES as usize / line.len()) + 10;
        std::fs::write(&path, line.repeat(n)).unwrap();
        let got = tail(&path, usize::MAX).unwrap();
        assert!(got.len() < n && got.len() >= n - 11, "{} of {n}", got.len());
        let _ = std::fs::remove_dir_all(&d);
    }
}
