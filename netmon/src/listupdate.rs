//! `netmon-blocklist-update`: downloads the host block lists that have a
//! `url` in the rules file or in a profile, checks each download with the
//! list parser, and replaces the old file only if the new one is good.
//! netmond reads the lists again on `systemctl reload netmond`.

use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use clap::Parser;

use crate::{blocklist, monitor, rulefile};

/// Downloads the host block lists that have a url in the rules file or in
/// a rule profile.
#[derive(Parser)]
#[command(version)]
struct UpdateArgs {
    /// Rules file; the profiles are in the directory `profiles` next to it.
    #[arg(long, value_name = "PATH", default_value = rulefile::DEFAULT_PATH)]
    rules: PathBuf,
}

/// Entry point of the `netmon-blocklist-update` binary. Fails if any list
/// could not be updated; the others are updated anyway.
pub fn run() -> anyhow::Result<()> {
    let args = UpdateArgs::parse();
    let (lists, mut errors) = sources(&args.rules);
    let total = lists.len() + errors.len();
    if lists.is_empty() && errors.is_empty() {
        println!("netmon-blocklist-update: no [[blocklist]] with a url");
        return Ok(());
    }
    for (path, url) in &lists {
        match update(Path::new(path), url) {
            Ok(n) => println!("netmon-blocklist-update: {path}: {n} names from {url}"),
            Err(e) => errors.push(format!("{path}: {e}")),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        for e in &errors {
            eprintln!("netmon-blocklist-update: {e}");
        }
        anyhow::bail!("{} of {total} lists not updated", errors.len())
    }
}

/// The lists with a url (path -> url) from the rules file and every
/// profile, and the problems found. A path with two different urls is a
/// problem and is not updated.
fn sources(rules: &Path) -> (BTreeMap<String, String>, Vec<String>) {
    let mut files = vec![rules.to_path_buf()];
    let dir = rules.with_file_name(monitor::PROFILES_DIR);
    if let Ok(entries) = std::fs::read_dir(&dir) {
        let mut profiles: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|x| x == "toml")
                    && p.file_stem().and_then(|s| s.to_str()).is_some_and(|s| monitor::check_profile_name(s).is_ok())
            })
            .collect();
        profiles.sort();
        files.extend(profiles);
    }
    let mut lists: BTreeMap<String, String> = BTreeMap::new();
    let mut errors = Vec::new();
    let mut conflicts = Vec::new();
    for f in &files {
        let parsed = match rulefile::read(f, f != rules) {
            Ok(Some(text)) => rulefile::parse(&text),
            Ok(None) => continue,
            Err(e) => Err(e),
        };
        match parsed {
            Ok(p) => {
                for b in p.blocklists.into_iter().filter(|b| !b.url.is_empty()) {
                    match lists.get(&b.path) {
                        Some(u) if *u != b.url => conflicts.push(b.path.clone()),
                        _ => {
                            lists.insert(b.path, b.url);
                        }
                    }
                }
            }
            Err(e) => errors.push(format!("{}: {e}", f.display())),
        }
    }
    for p in conflicts {
        if lists.remove(&p).is_some() {
            errors.push(format!("{p}: two different urls in the rules files"));
        }
    }
    (lists, errors)
}

/// Downloads `url` next to `path`, checks it, and renames it over `path`.
/// Returns the number of names.
fn update(path: &Path, url: &str) -> Result<usize, String> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).ok_or("no directory")?;
    let name = path.file_name().and_then(|n| n.to_str()).ok_or("no file name")?;
    let tmp = dir.join(format!(".{name}.download-{}", std::process::id()));
    let result = download_and_check(&tmp, url).and_then(|n| {
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(n)
    });
    let _ = std::fs::remove_file(&tmp);
    result
}

fn download_and_check(tmp: &Path, url: &str) -> Result<usize, String> {
    let out = Command::new("curl")
        .args(["-fsSL", "--proto", "=https,file", "--proto-redir", "=https", "--max-time", "300", "--retry", "2", "--max-filesize"])
        .arg(blocklist::MAX_FILE_BYTES.to_string())
        .arg("-o")
        .arg(tmp)
        .arg("--")
        .arg(url)
        .output()
        .map_err(|e| format!("run curl: {e}"))?;
    if !out.status.success() {
        return Err(format!("download failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let text = std::fs::read_to_string(tmp).map_err(|e| format!("read download: {e}"))?;
    let (names, _) = blocklist::parse(&text, blocklist::MAX_NAMES)?;
    if names.is_empty() {
        return Err("the download holds no hostname; the old file stays".into());
    }
    Ok(names.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let _fs = crate::test_fs_lock();
        let d = std::env::temp_dir().join(format!("netmon-listupdate-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("profiles")).unwrap();
        d
    }

    #[test]
    fn collects_urls_from_rules_and_profiles() {
        rulefile::TRUST_OWN_FILES.with(|t| t.set(true));
        let d = dir("sources");
        let rules = d.join("rules.toml");
        std::fs::write(&rules, "[[blocklist]]\npath = \"/l/a.txt\"\nurl = \"https://x.example/a\"\n\n[[blocklist]]\npath = \"/l/local.txt\"\n").unwrap();
        std::fs::write(d.join("profiles/home.toml"), "[[blocklist]]\npath = \"/l/b.txt\"\nurl = \"https://x.example/b\"\n\n[[blocklist]]\npath = \"/l/a.txt\"\nurl = \"https://x.example/a\"\n").unwrap();
        std::fs::write(d.join("profiles/work.toml"), "[[blocklist]]\npath = \"/l/b.txt\"\nurl = \"https://other.example/b\"\n").unwrap();
        std::fs::write(d.join("profiles/Bad Name.toml"), "not toml [").unwrap();
        let (lists, errors) = sources(&rules);
        assert_eq!(lists.into_iter().collect::<Vec<_>>(), [("/l/a.txt".to_string(), "https://x.example/a".to_string())]);
        assert_eq!(errors, ["/l/b.txt: two different urls in the rules files"]);
        rulefile::TRUST_OWN_FILES.with(|t| t.set(false));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn replaces_only_with_a_good_download() {
        let d = dir("update");
        let list = d.join("list.txt");
        std::fs::write(&list, "old.example\n").unwrap();
        let good = d.join("good.txt");
        std::fs::write(&good, "0.0.0.0 ads.example\n0.0.0.0 tracker.example\n").unwrap();
        let empty = d.join("empty.txt");
        std::fs::write(&empty, "# nothing here\n").unwrap();
        let url = |p: &Path| format!("file://{}", p.display());
        assert!(update(&list, &url(&empty)).unwrap_err().contains("no hostname"));
        assert!(update(&list, &url(&d.join("missing.txt"))).unwrap_err().contains("download failed"));
        assert_eq!(std::fs::read_to_string(&list).unwrap(), "old.example\n", "the old file stays");
        assert_eq!(update(&list, &url(&good)), Ok(2));
        assert!(std::fs::read_to_string(&list).unwrap().contains("ads.example"));
        assert_eq!(std::fs::metadata(&list).unwrap().permissions().mode() & 0o777, 0o644);
        let left: Vec<_> = std::fs::read_dir(&d).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("download")).collect();
        assert!(left.is_empty(), "no temporary file left");
        let _ = std::fs::remove_dir_all(&d);
    }
}
