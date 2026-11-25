//! The rules file, `/etc/netmon/rules.toml` by default. netmon runs as root,
//! so whoever can write this file controls the firewall: it must belong to
//! root and must not be writable by group or others, and the same holds for
//! its directory.

use std::{
    fmt::Write as _,
    fs::{DirBuilder, OpenOptions},
    io::{self, Write as _},
    net::IpAddr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

use netmon_common::{IPPROTO_TCP, IPPROTO_UDP};
use serde::Deserialize;

use crate::rules::{Action, Dir, Match, Rules, proto_name};

pub const DEFAULT_PATH: &str = "/etc/netmon/rules.toml";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    /// Action for TCP and UDP traffic no rule matches.
    default: Option<RawAction>,
    #[serde(default)]
    rule: Vec<toml::Spanned<RawRule>>,
    /// Blocked hostnames.
    #[serde(default)]
    host: Vec<toml::Spanned<RawHost>>,
    /// Host block lists.
    #[serde(default)]
    blocklist: Vec<toml::Spanned<RawBlocklist>>,
    /// When netmond sends alerts.
    alerts: Option<toml::Spanned<RawAlerts>>,
    /// Bandwidth limits per exe.
    #[serde(default)]
    limit: Vec<toml::Spanned<RawLimit>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimit {
    exe: String,
    up_mb: Option<f64>,
    down_mb: Option<f64>,
    #[serde(default)]
    comment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAlerts {
    rate_mb: Option<f64>,
    rate_seconds: Option<u32>,
    #[serde(default)]
    new_country: bool,
    #[serde(default)]
    new_device: bool,
    #[serde(default)]
    device_changes: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBlocklist {
    /// Absolute path of the list file.
    path: String,
    #[serde(default)]
    comment: String,
    /// Where netmon-blocklist-update downloads the list (https only).
    url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHost {
    /// `name.example.com` or `*.example.com`.
    name: String,
    #[serde(default)]
    comment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    action: RawAction,
    /// Absolute exe path.
    process: Option<String>,
    /// IP address or network in CIDR notation.
    remote: Option<String>,
    port: Option<RawPort>,
    proto: Option<String>,
    /// "out": this host opened the connection; "in": the remote host did.
    direction: Option<RawDir>,
    #[serde(default)]
    comment: String,
    /// End time, a TOML date and time in UTC, for example
    /// 2026-11-24T10:00:00Z.
    until: Option<toml::value::Datetime>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawDir {
    Out,
    In,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawAction {
    Allow,
    Deny,
    Ask,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawPort {
    One(u16),
    /// "8000-8100" or "443".
    Range(String),
}

#[derive(Debug, Default, PartialEq)]
pub struct RulesFile {
    /// None: the file does not say; netmon keeps allow.
    pub default: Option<Action>,
    pub rules: Vec<FileRule>,
    pub hosts: Vec<FileHost>,
    pub blocklists: Vec<FileBlocklist>,
    /// None: the file has no `[alerts]` table.
    pub alerts: Option<crate::rules::AlertConfig>,
    pub limits: Vec<FileLimit>,
}

#[derive(Debug, PartialEq)]
pub struct FileLimit {
    /// 1-based line of the `[[limit]]` header.
    pub line: usize,
    pub exe: String,
    pub up_mb: Option<f64>,
    pub down_mb: Option<f64>,
    pub comment: String,
}

#[derive(Debug, PartialEq)]
pub struct FileBlocklist {
    /// 1-based line of the `[[blocklist]]` header.
    pub line: usize,
    pub path: String,
    pub comment: String,
    /// Download URL, empty if none.
    pub url: String,
}

#[derive(Debug, PartialEq)]
pub struct FileHost {
    /// 1-based line of the `[[host]]` header.
    pub line: usize,
    pub pattern: String,
    pub comment: String,
}

#[derive(Debug, PartialEq)]
pub struct FileRule {
    /// 1-based line of the rule's `[[rule]]` header.
    pub line: usize,
    pub action: Action,
    pub m: Match,
    pub comment: String,
    /// End time, seconds since 1970 (UTC).
    pub until: Option<u64>,
}

/// Reads the file after checking who may write it. `Ok(None)`: the file
/// does not exist and `required` is false.
pub fn read(path: &Path, required: bool) -> Result<Option<String>, String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound && !required => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if let Some(why) = unsafe_owner(meta.uid(), meta.mode()) {
        return Err(format!("file {why}"));
    }
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let dmeta = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if let Some(why) = unsafe_owner(dmeta.uid(), dmeta.mode()) {
        return Err(format!("directory {} {why}", dir.display()));
    }
    std::fs::read_to_string(path).map(Some).map_err(|e| e.to_string())
}

#[cfg(test)]
thread_local! {
    /// Tests that load rules files of their own set this: then files of
    /// the test user count as root's. Per thread, so other tests still see
    /// the real check.
    pub(crate) static TRUST_OWN_FILES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Does `uid` own trusted files? Root only (and the test user in tests that
/// ask for it).
fn trusted_uid(uid: u32) -> bool {
    #[cfg(test)]
    // SAFETY: geteuid has no preconditions.
    if TRUST_OWN_FILES.with(|t| t.get()) && uid == unsafe { libc::geteuid() } {
        return true;
    }
    uid == 0
}

/// Why a file or directory with this owner and mode must not be trusted.
fn unsafe_owner(uid: u32, mode: u32) -> Option<&'static str> {
    if !trusted_uid(uid) {
        Some("is not owned by root")
    } else if mode & 0o022 != 0 {
        Some("is writable by group or others")
    } else {
        None
    }
}

/// Parses the file. Errors name the line.
pub fn parse(text: &str) -> Result<RulesFile, String> {
    let raw: RawFile = toml::from_str(text).map_err(|e| {
        let line = e.span().map(|s| line_of(text, s.start)).unwrap_or(0);
        format!("line {line}: {}", e.message().trim())
    })?;
    let rules = raw
        .rule
        .into_iter()
        .map(|r| {
            let line = line_of(text, r.span().start);
            let r = r.into_inner();
            let until = r.until.as_ref().map(unix_secs).transpose().map_err(|e| format!("line {line}: {e}"))?;
            convert(r)
                .map(|(action, m, comment)| FileRule { line, action, m, comment, until })
                .map_err(|e| format!("line {line}: {e}"))
        })
        .collect::<Result<_, _>>()?;
    let hosts = raw
        .host
        .into_iter()
        .map(|h| {
            let line = line_of(text, h.span().start);
            let h = h.into_inner();
            crate::rules::host_pattern(&h.name)
                .map(|pattern| FileHost { line, pattern, comment: h.comment })
                .map_err(|e| format!("line {line}: {e}"))
        })
        .collect::<Result<_, _>>()?;
    let blocklists = raw
        .blocklist
        .into_iter()
        .map(|b| {
            let line = line_of(text, b.span().start);
            let b = b.into_inner();
            if !b.path.starts_with('/') {
                return Err(format!("line {line}: blocklist path {:?}: use an absolute path", b.path));
            }
            let url = b.url.unwrap_or_default();
            if !url.is_empty() && (!url.starts_with("https://") || url.chars().any(|c| c.is_control() || c.is_whitespace())) {
                return Err(format!("line {line}: blocklist url {url:?}: use an https:// URL"));
            }
            Ok(FileBlocklist { line, path: b.path, comment: b.comment, url })
        })
        .collect::<Result<_, _>>()?;
    let alerts = raw
        .alerts
        .map(|a| {
            let line = line_of(text, a.span().start);
            let a = a.into_inner();
            if a.rate_mb.is_some_and(|r| !(r > 0.0 && r.is_finite())) {
                return Err(format!("line {line}: alerts rate_mb: use a number above 0"));
            }
            if a.rate_seconds.is_some_and(|s| !(1..=3600).contains(&s)) {
                return Err(format!("line {line}: alerts rate_seconds: use 1 to 3600"));
            }
            Ok(crate::rules::AlertConfig {
                rate_mb: a.rate_mb,
                rate_seconds: a.rate_seconds.unwrap_or(0),
                new_country: a.new_country,
                new_device: a.new_device,
                device_changes: a.device_changes,
            })
        })
        .transpose()?;
    let limits = raw
        .limit
        .into_iter()
        .map(|l| {
            let line = line_of(text, l.span().start);
            let l = l.into_inner();
            if l.up_mb.is_none() && l.down_mb.is_none() {
                return Err(format!("line {line}: limit: give up_mb, down_mb or both"));
            }
            crate::rules::Match { exe: Some(l.exe.clone()), ..Default::default() }.check().map_err(|e| format!("line {line}: limit {e}"))?;
            for v in [l.up_mb, l.down_mb].into_iter().flatten() {
                crate::rules::limit_rate(v).map_err(|e| format!("line {line}: {e}"))?;
            }
            Ok(FileLimit { line, exe: l.exe, up_mb: l.up_mb, down_mb: l.down_mb, comment: l.comment })
        })
        .collect::<Result<_, _>>()?;
    Ok(RulesFile { default: raw.default.map(action), rules, hosts, blocklists, alerts, limits })
}

fn action(a: RawAction) -> Action {
    match a {
        RawAction::Allow => Action::Allow,
        RawAction::Deny => Action::Deny,
        RawAction::Ask => Action::Ask,
    }
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count() + 1
}

fn convert(r: RawRule) -> Result<(Action, Match, String), String> {
    let action = action(r.action);
    if action == Action::Ask {
        return Err("action \"ask\" is only allowed as the top-level default".into());
    }
    let dir = r.direction.map(|d| match d {
        RawDir::Out => Dir::Out,
        RawDir::In => Dir::In,
    });
    let proto = match r.proto.as_deref() {
        None => None,
        Some("tcp") => Some(IPPROTO_TCP),
        Some("udp") => Some(IPPROTO_UDP),
        Some(p) => return Err(format!("proto {p:?}: use \"tcp\" or \"udp\"")),
    };
    let ports = match r.port {
        None => None,
        Some(RawPort::One(p)) => Some((p, p)),
        Some(RawPort::Range(s)) => Some(port_range(&s)?),
    };
    let net = r.remote.as_deref().map(network).transpose()?;
    let m = Match { net, proto, ports, exe: r.process, dir };
    m.check()?;
    Ok((action, m, r.comment))
}

/// A TOML date and time with an offset as seconds since 1970 (UTC).
fn unix_secs(d: &toml::value::Datetime) -> Result<u64, String> {
    let bad = || format!("until {d}: use a date and time in UTC, like 2026-11-24T10:00:00Z");
    let (Some(date), Some(time), Some(offset)) = (d.date, d.time, d.offset) else { return Err(bad()) };
    let off_min: i64 = match offset {
        toml::value::Offset::Z => 0,
        toml::value::Offset::Custom { minutes } => minutes.into(),
    };
    let days = days_from_civil(date.year.into(), date.month.into(), date.day.into());
    let secs = days * 86_400 + i64::from(time.hour) * 3600 + i64::from(time.minute) * 60 + i64::from(time.second.unwrap_or(0))
        - off_min * 60;
    u64::try_from(secs).map_err(|_| bad())
}

/// Seconds since 1970 as a TOML date and time in UTC.
pub(crate) fn utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Days since 1970-01-01 of a date (proleptic Gregorian calendar). From
/// Howard Hinnant's `days_from_civil`.
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day since 1970-01-01. Inverse of `days_from_civil`.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { yoe + era * 400 + 1 } else { yoe + era * 400 }, m, d)
}

fn port_range(s: &str) -> Result<(u16, u16), String> {
    let bad = || format!("port {s:?}: use a number or a range like \"8000-8100\"");
    let (lo, hi) = s.split_once('-').unwrap_or((s, s));
    let lo = lo.trim().parse().map_err(|_| bad())?;
    let hi = hi.trim().parse().map_err(|_| bad())?;
    Ok((lo, hi))
}

/// "1.2.3.4", "10.0.0.0/8", "2001:db8::/32". Host bits must be zero, so a
/// typo like 10.1.0.0/8 is caught instead of silently widened.
fn network(s: &str) -> Result<(IpAddr, u8), String> {
    let (ip, len) = match s.split_once('/') {
        Some((ip, len)) => (ip, Some(len)),
        None => (s, None),
    };
    let ip: IpAddr = ip.trim().parse().map_err(|_| format!("remote {s:?}: not an IP address or network"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match len {
        None => max,
        Some(l) => match l.trim().parse::<u8>() {
            Ok(l) if l <= max => l,
            _ => return Err(format!("remote {s:?}: prefix must be 0-{max}")),
        },
    };
    let masked = mask(ip, len);
    if masked != ip {
        return Err(format!("remote {s:?}: host bits set, did you mean {masked}/{len}?"));
    }
    Ok((ip, len))
}

/// The rules as a rules file, in match order, without temporary rules.
/// Only `comment` fields survive; other `#` comments of a hand-written
/// file are not kept.
pub fn render(rules: &Rules) -> String {
    let q = |s: &str| toml::Value::String(s.to_string()).to_string();
    let mut out = String::from("# netmon rules, first match wins. Written by netmon.\n");
    let _ = writeln!(out, "default = {}", q(&rules.default.to_string()));
    let a = &rules.alerts;
    if a.any() || a.new_device || a.device_changes || a.rate_seconds != 0 {
        out.push_str("\n[alerts]\n");
        if let Some(r) = a.rate_mb {
            let _ = writeln!(out, "rate_mb = {r:?}");
        }
        if a.rate_seconds != 0 {
            let _ = writeln!(out, "rate_seconds = {}", a.rate_seconds);
        }
        if a.new_country {
            out.push_str("new_country = true\n");
        }
        if a.new_device {
            out.push_str("new_device = true\n");
        }
        if a.device_changes {
            out.push_str("device_changes = true\n");
        }
    }
    for r in rules.rules.iter().filter(|r| !r.temporary) {
        let m = &r.m;
        let _ = write!(out, "\n[[rule]]\naction = {}\n", q(&r.action.to_string()));
        if let Some(d) = m.dir {
            let _ = writeln!(out, "direction = {}", q(if d == Dir::In { "in" } else { "out" }));
        }
        if let Some(p) = &m.exe {
            let _ = writeln!(out, "process = {}", q(p));
        }
        if let Some((ip, len)) = m.net {
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let net = if len == max { ip.to_string() } else { format!("{ip}/{len}") };
            let _ = writeln!(out, "remote = {}", q(&net));
        }
        if let Some(p) = m.proto {
            let _ = writeln!(out, "proto = {}", q(proto_name(p)));
        }
        match m.ports {
            Some((lo, hi)) if lo == hi => {
                let _ = writeln!(out, "port = {lo}");
            }
            Some((lo, hi)) => {
                let _ = writeln!(out, "port = {}", q(&format!("{lo}-{hi}")));
            }
            None => {}
        }
        if !r.comment.is_empty() {
            let _ = writeln!(out, "comment = {}", q(&r.comment));
        }
        if let Some(u) = r.until {
            let _ = writeln!(out, "until = {}", utc(u));
        }
    }
    for h in &rules.hosts {
        let _ = write!(out, "\n[[host]]\nname = {}\n", q(&h.pattern));
        if !h.comment.is_empty() {
            let _ = writeln!(out, "comment = {}", q(&h.comment));
        }
    }
    for l in &rules.limits {
        let _ = write!(out, "\n[[limit]]\nexe = {}\n", q(&l.exe));
        if let Some(v) = l.up_mb {
            let _ = writeln!(out, "up_mb = {v:?}");
        }
        if let Some(v) = l.down_mb {
            let _ = writeln!(out, "down_mb = {v:?}");
        }
        if !l.comment.is_empty() {
            let _ = writeln!(out, "comment = {}", q(&l.comment));
        }
    }
    for l in &rules.blocklists {
        let _ = write!(out, "\n[[blocklist]]\npath = {}\n", q(&l.path));
        if !l.url.is_empty() {
            let _ = writeln!(out, "url = {}", q(&l.url));
        }
        if !l.comment.is_empty() {
            let _ = writeln!(out, "comment = {}", q(&l.comment));
        }
    }
    out
}

/// Writes `text` to `path`: the directory is created (0755) if missing and
/// must pass the same owner check as on load. The text goes to a new temp
/// file (mode 0644, never through a symlink), is synced, then renamed over
/// the file, so a crash leaves the old or the new file, never half of one.
pub fn save(path: &Path, text: &str) -> Result<(), String> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if !dir.exists() {
        DirBuilder::new().mode(0o755).create(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let meta = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if let Some(why) = unsafe_owner(meta.uid(), meta.mode()) {
        return Err(format!("directory {} {why}", dir.display()));
    }
    write_atomic(dir, path, text)
}

fn write_atomic(dir: &Path, path: &Path, text: &str) -> Result<(), String> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let r = (|| -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        // The umask may have narrowed the mode.
        f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(|e| e.to_string())
}

pub(crate) fn mask(ip: IpAddr, len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let m = u32::MAX.checked_shl(32 - len as u32).unwrap_or(0);
            IpAddr::V4((u32::from(a) & m).into())
        }
        IpAddr::V6(a) => {
            let m = u128::MAX.checked_shl(128 - len as u32).unwrap_or(0);
            IpAddr::V6((u128::from(a) & m).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
# curl may reach HTTPS only.
[[rule]]
action = "allow"
process = "/usr/bin/curl"
proto = "tcp"
port = 443
comment = "web"

[[rule]]
action = "deny"
process = "/usr/bin/curl"

[[rule]]
action = "deny"
remote = "10.0.0.0/8"
port = "8000-8100"

[[rule]]
action = "deny"
remote = "2001:db8::1"
"#;

    #[test]
    fn limits_parse_check_and_round_trip() {
        let f = parse("[[limit]]\nexe = \"/usr/bin/steam\"\ndown_mb = 5\nup_mb = 0.5\ncomment = \"games\"\n").unwrap();
        assert_eq!(
            f.limits,
            vec![FileLimit { line: 1, exe: "/usr/bin/steam".into(), up_mb: Some(0.5), down_mb: Some(5.0), comment: "games".into() }]
        );
        assert!(err("[[limit]]\nexe = \"/usr/bin/x\"\n").contains("give up_mb"));
        assert!(err("[[limit]]\nexe = \"x\"\ndown_mb = 1\n").contains("absolute path"));
        assert!(err("[[limit]]\nexe = \"/x\"\ndown_mb = 0\n").contains("0.01 to"));
        assert!(err("[[limit]]\nexe = \"/x\"\nrate = 1\n").starts_with("line"), "unknown field");
        let mut rules = Rules::default();
        rules.set_limit("/usr/bin/steam", Some(0.5), Some(5.0), "games").unwrap();
        let back = parse(&render(&rules)).unwrap();
        assert_eq!((back.limits[0].up_mb, back.limits[0].down_mb, back.limits[0].comment.as_str()), (Some(0.5), Some(5.0), "games"));
    }

    #[test]
    fn alerts_table_parses_checks_and_round_trips() {
        let f = parse("default = \"allow\"\n\n[alerts]\nrate_mb = 50\nnew_country = true\nnew_device = true\ndevice_changes = true\n\n[[rule]]\naction = \"deny\"\nport = 25\n").unwrap();
        let a = f.alerts.unwrap();
        assert_eq!((a.rate_mb, a.rate_seconds(), a.new_country, a.new_device, a.device_changes), (Some(50.0), 10, true, true, true));
        assert!(parse("").unwrap().alerts.is_none());
        assert!(err("[alerts]\nrate_mb = 0\n").contains("above 0"));
        assert!(err("[alerts]\nrate_seconds = 0\n").contains("1 to 3600"));
        assert!(err("[alerts]\nrate = 5\n").starts_with("line"), "unknown field");
        let mut rules = Rules::default();
        rules.alerts = a;
        let back = parse(&render(&rules)).unwrap();
        assert_eq!(back.alerts, Some(a));
        assert!(!render(&Rules::default()).contains("[alerts]"));
    }

    #[test]
    fn blocklist_url_round_trips_and_must_be_https() {
        let f = parse("[[blocklist]]\npath = \"/etc/netmon/lists/a.txt\"\nurl = \"https://x.example/hosts\"\n").unwrap();
        assert_eq!(f.blocklists[0].url, "https://x.example/hosts");
        let mut rules = Rules::default();
        let id = rules.add_blocklist("/etc/netmon/lists/a.txt", "", Ok((Default::default(), 0))).unwrap();
        rules.blocklists.iter_mut().find(|b| b.id == id).unwrap().url = "https://x.example/hosts".into();
        assert_eq!(parse(&render(&rules)).unwrap().blocklists[0].url, "https://x.example/hosts");
        for bad in ["http://x.example/hosts", "file:///etc/passwd", "https://x.example/a b"] {
            let e = err(&format!("[[blocklist]]\npath = \"/a\"\nurl = \"{bad}\"\n"));
            assert!(e.contains("use an https:// URL"), "{bad}: {e}");
        }
    }

    #[test]
    fn until_reads_and_writes_utc() {
        let f = parse("[[rule]]\naction = \"deny\"\nport = 25\nuntil = 2026-11-24T10:00:00Z\n").unwrap();
        assert_eq!(f.rules[0].until, Some(1_795_514_400));
        let f = parse("[[rule]]\naction = \"deny\"\nport = 25\nuntil = 2026-11-24T12:00:00+02:00\n").unwrap();
        assert_eq!(f.rules[0].until, Some(1_795_514_400), "offset applied");
        assert!(err("[[rule]]\naction = \"deny\"\nuntil = 2026-11-24\n").contains("use a date and time in UTC"));
        assert_eq!(utc(1_795_514_400), "2026-11-24T10:00:00Z");
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(951_782_400), "2000-02-29T00:00:00Z", "leap day");
        for days in [-1, 0, 59, 60, 365, 11_016, 20_416, 100_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        let mut rules = Rules::default();
        let id = rules.insert(0, Action::Deny, Match { ports: Some((25, 25)), ..Match::default() }, "").unwrap();
        rules.set_until(id, Some(1_795_514_400));
        let text = render(&rules);
        assert!(text.contains("\nuntil = 2026-11-24T10:00:00Z\n"), "{text}");
        assert_eq!(parse(&text).unwrap().rules[0].until, Some(1_795_514_400));
    }

    #[test]
    fn default_and_direction() {
        let f = parse("default = \"deny\"\n\n[[rule]]\naction = \"allow\"\ndirection = \"out\"\n").unwrap();
        assert_eq!(f.default, Some(Action::Deny));
        assert_eq!(f.rules[0].m.to_string(), "out");
        assert_eq!(parse(EXAMPLE).unwrap().default, None);
        assert!(err("[[rule]]\naction = \"deny\"\ndirection = \"both\"\n").starts_with("line 3:"));
        assert!(err("default = \"block\"\n").starts_with("line 1:"));
        assert_eq!(parse("default = \"ask\"\n").unwrap().default, Some(Action::Ask));
        assert!(err("[[rule]]\naction = \"ask\"\n").contains("only allowed as the top-level default"));
    }

    #[test]
    fn parses_rules_in_order() {
        let r = parse(EXAMPLE).unwrap().rules;
        assert_eq!(r.len(), 4);
        assert_eq!(r[0].line, 3);
        assert_eq!(r[0].action, Action::Allow);
        assert_eq!(r[0].m.to_string(), "exe /usr/bin/curl tcp port 443");
        assert_eq!(r[0].comment, "web");
        assert_eq!(r[1].m.to_string(), "exe /usr/bin/curl");
        assert_eq!(r[2].m.to_string(), "port 8000-8100 net 10.0.0.0/8");
        assert_eq!(r[3].m.to_string(), "host 2001:db8::1");
        assert_eq!(parse("").unwrap(), RulesFile::default(), "empty file: no rules");
    }

    fn err(text: &str) -> String {
        parse(text).unwrap_err()
    }

    #[test]
    fn errors_name_the_line() {
        assert!(err("[[rule]]\naction = \"drop\"\n").starts_with("line 2:"), "{}", err("[[rule]]\naction = \"drop\"\n"));
        let e = err("[[rule]]\naction = \"deny\"\n\n[[rule]]\naction = \"deny\"\nremote = \"10.1.0.0/8\"\n");
        assert!(e.starts_with("line 4:") && e.contains("10.0.0.0/8"), "{e}");
        let e = err("[[rule]]\naction = \"deny\"\nproces = \"/bin/x\"\n");
        assert!(e.starts_with("line 3:") && e.contains("proces"), "unknown key: {e}");
        let e = err("[[rule]]\naction = \"deny\"\nprocess = \"curl\"\n");
        assert!(e.starts_with("line 1:") && e.contains("absolute"), "{e}");
        assert!(err("[[rule]]\naction = \"deny\"\nport = \"9-1\"\n").contains("port range"));
        assert!(err("[[rule]]\naction = \"deny\"\nport = 0\n").contains("port range"));
        assert!(err("[[rule]]\naction = \"deny\"\nport = 70000\n").starts_with("line 3:"));
        assert!(err("[[rule]]\naction = \"deny\"\nproto = \"icmp\"\n").contains("tcp"));
        assert!(err("[[rule]]\naction = \"deny\"\nremote = \"1.2.3.4/33\"\n").contains("prefix"));
        assert!(err("[[rule]]\nremote = \"1.2.3.4\"\n").starts_with("line 1:"), "missing action");
        assert!(err("defaults = \"deny\"\n").starts_with("line 1:"), "unknown top-level key");
    }

    #[test]
    fn render_round_trips() {
        let mut rules = Rules::default();
        rules.default = Action::Deny;
        for f in parse(EXAMPLE).unwrap().rules {
            rules.insert(usize::MAX, f.action, f.m, &f.comment).unwrap();
        }
        let m = Match { dir: Some(Dir::In), ports: Some((22, 22)), proto: Some(IPPROTO_TCP), ..Match::default() };
        rules.insert(0, Action::Allow, m, "say \"hi\" C:\\dir").unwrap();
        let text = render(&rules);
        let back = parse(&text).unwrap();
        assert_eq!(back.default, Some(Action::Deny));
        assert_eq!(back.rules.len(), rules.rules.len());
        for (a, b) in back.rules.iter().zip(&rules.rules) {
            assert_eq!((a.action, &a.m, &a.comment), (b.action, &b.m, &b.comment), "{text}");
        }
    }

    #[test]
    fn host_blocks_round_trip_and_are_checked() {
        let mut rules = Rules::default();
        rules.add_host("*.ads.example", "ads").unwrap();
        rules.add_host("tracker.example.com", "").unwrap();
        let back = parse(&render(&rules)).unwrap();
        let got: Vec<_> = back.hosts.iter().map(|h| (h.pattern.as_str(), h.comment.as_str())).collect();
        assert_eq!(got, vec![("*.ads.example", "ads"), ("tracker.example.com", "")]);
        let e = parse("[[host]]\nname = \"a b\"\n").unwrap_err();
        assert!(e.starts_with("line 1:") && e.contains("hostname"), "{e}");
        assert!(parse("[[host]]\nname = \"x.com\"\nport = 1\n").is_err(), "unknown key");
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let _fs = crate::test_fs_lock();
        let dir = std::env::temp_dir().join(format!("netmon-save-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.toml");
        write_atomic(&dir, &path, "a").unwrap();
        write_atomic(&dir, &path, "b").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "b");
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names.len(), 1, "{names:?}");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
        // Tests run as a normal user: save() refuses the user-owned dir.
        assert!(save(&path, "c").unwrap_err().contains("not owned by root"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "b");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn owner_and_mode_checks() {
        assert_eq!(unsafe_owner(0, 0o100644), None);
        assert_eq!(unsafe_owner(0, 0o040755), None);
        assert!(unsafe_owner(1000, 0o100644).is_some());
        assert!(unsafe_owner(0, 0o100664).is_some(), "group writable");
        assert!(unsafe_owner(0, 0o040777).is_some(), "world writable dir");
    }

    #[test]
    fn missing_file() {
        let p = Path::new("/nonexistent/netmon/rules.toml");
        assert_eq!(read(p, false), Ok(None));
        assert!(read(p, true).is_err());
    }
}
