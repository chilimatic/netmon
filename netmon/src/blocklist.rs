//! Host block lists: files with many hostnames to block, for example the
//! StevenBlack hosts file or an OISD list. Each name blocks itself and
//! every name below it, like a `*.name` host block.
//!
//! Formats, one entry per line:
//! - hosts file: `0.0.0.0 ads.example.com` (more names may follow)
//! - adblock: `||ads.example.com^` (options after `^` are ignored)
//! - plain: `ads.example.com`, or `*.ads.example.com`
//!
//! `#` starts a comment; lines starting with `!` or `[` are skipped
//! (adblock comments and headers). Other lines that do not hold a hostname
//! are counted as skipped.

use std::collections::HashSet;

/// Names in all lists together at most.
pub const MAX_NAMES: usize = 2_000_000;
/// Largest list file read.
pub const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;

/// Hosts-file names that are not blocks.
const LOCAL_NAMES: [&str; 6] = ["localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback"];

/// The names of a list file, and the number of lines that held none.
pub fn parse(text: &str, max: usize) -> Result<(HashSet<String>, usize), String> {
    let mut names = HashSet::new();
    let mut skipped = 0;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }
        let mut found = false;
        for cand in candidates(line) {
            if cand.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            if LOCAL_NAMES.contains(&cand) || cand.starts_with("ip6-") {
                found = true;
                continue;
            }
            let Ok(p) = crate::rules::host_pattern(cand) else { continue };
            let name = p.strip_prefix("*.").map(str::to_string).unwrap_or(p);
            // A bare top-level name (a typo, or "com") would block too much.
            if !name.contains('.') {
                continue;
            }
            found = true;
            if names.len() >= max {
                return Err(format!("more than {max} names"));
            }
            names.insert(name);
        }
        if !found {
            skipped += 1;
        }
    }
    Ok((names, skipped))
}

/// The hostnames a line may hold, by format.
fn candidates(line: &str) -> Vec<&str> {
    if let Some(rest) = line.strip_prefix("||") {
        return vec![rest.split(['^', '$', '/']).next().unwrap_or("")];
    }
    let mut words = line.split_whitespace();
    let first = words.next().unwrap_or("");
    if first.parse::<std::net::IpAddr>().is_ok() {
        return words.collect();
    }
    if words.next().is_none() { vec![first] } else { Vec::new() }
}

/// Is `name` or a name above it in `names`? Case and a final dot do not
/// count.
pub fn contains(names: &HashSet<String>, name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let mut rest = name.as_str();
    loop {
        if names.contains(rest) {
            return true;
        }
        match rest.split_once('.') {
            // Stop before the top-level name: lists never block "com".
            Some((_, up)) if up.contains('.') => rest = up,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_hosts_adblock_and_plain_lines() {
        let text = "# StevenBlack\n127.0.0.1 localhost\n::1 ip6-localhost ip6-loopback\n0.0.0.0 ads.example.com tracker.example.net # two\n\
                    ! adblock comment\n[Adblock Plus 2.0]\n||Metrics.Example.org^\n||cdn.example.io^$third-party\n\
                    plain.example.com\n*.wild.example.com\nnot a host line\ncom\n0.0.0.0 0.0.0.0\n";
        let (names, skipped) = parse(text, 100).unwrap();
        let mut got: Vec<_> = names.into_iter().collect();
        got.sort();
        assert_eq!(
            got,
            [
                "ads.example.com",
                "cdn.example.io",
                "metrics.example.org",
                "plain.example.com",
                "tracker.example.net",
                "wild.example.com"
            ]
        );
        assert_eq!(skipped, 3, "the prose line, the bare top-level name and 0.0.0.0 0.0.0.0");
        assert!(parse("a.example\nb.example\nc.example\n", 2).unwrap_err().contains("more than 2"));
    }

    #[test]
    fn a_name_blocks_the_names_below_it() {
        let names: HashSet<String> = ["ads.example.com".to_string()].into();
        assert!(contains(&names, "ads.example.com"));
        assert!(contains(&names, "x.y.Ads.Example.com."));
        assert!(!contains(&names, "example.com"));
        assert!(!contains(&names, "badads.example.com"));
        let top: HashSet<String> = ["com".to_string()].into();
        assert!(!contains(&top, "example.com"), "never a top-level name");
    }
}
