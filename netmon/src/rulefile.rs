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
}

#[derive(Debug, PartialEq)]
pub struct FileRule {
    /// 1-based line of the rule's `[[rule]]` header.
    pub line: usize,
    pub action: Action,
    pub m: Match,
    pub comment: String,
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

/// Why a file or directory with this owner and mode must not be trusted.
fn unsafe_owner(uid: u32, mode: u32) -> Option<&'static str> {
    if uid != 0 {
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
            convert(r.into_inner())
                .map(|(action, m, comment)| FileRule { line, action, m, comment })
                .map_err(|e| format!("line {line}: {e}"))
        })
        .collect::<Result<_, _>>()?;
    Ok(RulesFile { default: raw.default.map(action), rules })
}

fn action(a: RawAction) -> Action {
    match a {
        RawAction::Allow => Action::Allow,
        RawAction::Deny => Action::Deny,
    }
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count() + 1
}

fn convert(r: RawRule) -> Result<(Action, Match, String), String> {
    let action = action(r.action);
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

/// The rules as a rules file, in match order. Only `comment` fields
/// survive; other `#` comments of a hand-written file are not kept.
pub fn render(rules: &Rules) -> String {
    let q = |s: &str| toml::Value::String(s.to_string()).to_string();
    let mut out = String::from("# netmon rules, first match wins. Written by netmon.\n");
    let _ = writeln!(out, "default = {}", q(&rules.default.to_string()));
    for r in &rules.rules {
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

fn mask(ip: IpAddr, len: u8) -> IpAddr {
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
    fn default_and_direction() {
        let f = parse("default = \"deny\"\n\n[[rule]]\naction = \"allow\"\ndirection = \"out\"\n").unwrap();
        assert_eq!(f.default, Some(Action::Deny));
        assert_eq!(f.rules[0].m.to_string(), "out");
        assert_eq!(parse(EXAMPLE).unwrap().default, None);
        assert!(err("[[rule]]\naction = \"deny\"\ndirection = \"both\"\n").starts_with("line 3:"));
        assert!(err("default = \"block\"\n").starts_with("line 1:"));
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
        rules.insert(0, Action::Allow, m, "say \"hi\"\nnext line").unwrap();
        let text = render(&rules);
        let back = parse(&text).unwrap();
        assert_eq!(back.default, Some(Action::Deny));
        assert_eq!(back.rules.len(), rules.rules.len());
        for (a, b) in back.rules.iter().zip(&rules.rules) {
            assert_eq!((a.action, &a.m, &a.comment), (b.action, &b.m, &b.comment), "{text}");
        }
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
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
