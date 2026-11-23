//! Rules: edits, the rules file, exe marks and the lockout guard.

use std::path::Path;

use super::*;

/// Ticks between two reads of /etc/resolv.conf for the guard.
pub(super) const GUARD_REFRESH: u64 = 5;

/// Inputs of the lockout guard.
#[derive(Default)]
pub(crate) struct Guard {
    pub(super) ssh: Option<String>,
    pub(super) ports: Vec<u16>,
    pub(super) resolv: String,
}

impl Guard {
    pub(super) fn endpoints(&self) -> Vec<rules::GuardEndpoint> {
        guard_endpoints(self.ssh.as_deref(), &self.resolv)
    }
}

pub(super) fn read_resolv() -> String {
    std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default()
}

/// The rules file did not load. netmond then does not start: exit code
/// 78 (EX_CONFIG) tells systemd not to restart it.
#[derive(Debug)]
pub struct RulesFileError(pub String);

impl std::fmt::Display for RulesFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}; netmond does not start, the rules of an earlier netmond stay in force", self.0)
    }
}

impl std::error::Error for RulesFileError {}

impl<K: Kernel> Monitor<K> {
    /// Adds the rule, or removes it if it exists.
    /// Blocks a hostname pattern. Saved with the rules (s).
    pub(crate) fn block_host(&mut self, pattern: &str, comment: &str) -> String {
        self.change_rules(|r| {
            r.add_host(pattern, comment)?;
            let p = rules::host_pattern(pattern)?;
            Ok(format!("blocked host {p} (s in the Rules or Hosts tab saves it)"))
        })
    }

    /// Reads every host block list again (SIGHUP, r in the Hosts tab).
    pub(crate) fn reload_blocklists(&mut self) -> String {
        if self.rules.blocklists.is_empty() {
            return "no blocklists in the rules file".into();
        }
        let mut left = crate::blocklist::MAX_NAMES;
        let mut parts = Vec::new();
        for l in &mut self.rules.blocklists {
            let names = read_blocklist(Path::new(&l.path), left);
            left -= names.as_ref().map_or(0, |(n, _)| n.len());
            l.set_names(names);
            parts.push(if l.error.is_empty() { format!("{} {}", l.path, l.count) } else { format!("{} failed: {}", l.path, l.error) });
        }
        let err = self.sync_host_blocks(Instant::now()).map(|e| format!("; {e}")).unwrap_or_default();
        format!("blocklists reloaded: {}{err}", parts.join(", "))
    }

    pub(crate) fn remove_host(&mut self, id: u32) -> String {
        if self.rules.blocklists.iter().any(|l| l.id == id) {
            let path = self.rules.remove_blocklist(id).unwrap_or_default();
            let err = self.sync_host_blocks(Instant::now()).map(|e| format!("; {e}")).unwrap_or_default();
            return format!("removed blocklist {path} (s saves the rules file without it){err}");
        }
        let mut name = String::new();
        let msg = self.change_rules(|r| {
            name = r.remove_host(id).ok_or("host block already removed")?;
            Ok(String::new())
        });
        if msg.is_empty() { format!("unblocked host {name}") } else { msg }
    }

    /// Writes the addresses of blocked hostnames to the kernel: new
    /// patterns match names learned before, removed patterns and old
    /// answers drop out. Fills the addresses and hits each pattern shows.
    pub(crate) fn sync_host_blocks(&mut self, now: Instant) -> Option<String> {
        if !self.rules.has_host_blocks() && self.blocked.is_empty() && self.kernel_blocked.is_empty() {
            return None;
        }
        let rules = &self.rules;
        for (ip, name, seen) in self.hosts.iter(now) {
            if rules.host_blocked(name) {
                self.blocked.entry(ip).or_insert_with(|| (name.to_string(), seen));
            }
        }
        for (k, name) in &self.sni {
            if rules.host_blocked(name) {
                let ip = procmap::normalize(collector::addr(k.family, &k.remote_addr, 0)).ip();
                self.blocked.insert(ip, (name.clone(), now));
            }
        }
        self.blocked.retain(|_, (name, seen)| rules.host_blocked(name) && now.duration_since(*seen) < names::KEEP);
        let want: HashSet<std::net::IpAddr> = self.blocked.keys().copied().collect();
        let add: Vec<_> = want.difference(&self.kernel_blocked).copied().collect();
        let remove: Vec<_> = self.kernel_blocked.difference(&want).copied().collect();
        let mut error = None;
        if !add.is_empty() || !remove.is_empty() {
            let failed = self.probe.set_blocked_addrs(&add, &remove);
            if !failed.is_empty() {
                error = Some(format!("{} addresses of blocked hosts not blocked: map full", failed.len()));
            }
            self.kernel_blocked = want.into_iter().filter(|ip| !failed.contains(ip)).collect();
        }
        let hits = self.probe.blocked_hits();
        for h in &mut self.rules.hosts {
            let mut addrs: Vec<_> =
                self.blocked.iter().filter(|(_, (n, _))| h.matches(n)).map(|(ip, _)| *ip).collect();
            addrs.sort();
            h.hits = addrs.iter().filter_map(|a| hits.get(a)).sum();
            h.addrs = addrs;
        }
        for l in &mut self.rules.blocklists {
            let addrs: Vec<_> = self.blocked.iter().filter(|(_, (n, _))| l.matches(n)).map(|(ip, _)| *ip).collect();
            l.hits = addrs.iter().filter_map(|a| hits.get(a)).sum();
            l.addrs = addrs.len();
        }
        error
    }

    pub(crate) fn toggle_block(&mut self, target: BlockTarget) -> String {
        if let Some(rule) = self.rules.find_block(&target) {
            return self.remove_rule(rule.id);
        }
        let msg = format!("blocked {target} (until the monitor stops; b again or Rules tab to undo)");
        self.change_rules(|r| r.block(target).map(|_| msg))
    }

    /// Rule `id` ends `secs` from now, or never (None).
    pub(crate) fn set_rule_timer(&mut self, id: u32, secs: Option<u64>) -> String {
        let until = secs.map(|s| rules::unix_now() + s);
        // Only the list changes, not the kernel table.
        if !self.rules.set_until(id, until) {
            return "no such rule".into();
        }
        let rule = self.rules.rules.iter().find(|r| r.id == id).map(|r| r.to_string()).unwrap_or_default();
        match secs {
            Some(s) => format!("{rule} ends in {}", rules::time_left(s, 0)),
            None => format!("{rule} has no end time"),
        }
    }

    /// Removes the rules whose end time passed. Returns a message for each
    /// change, empty if none ended.
    pub(crate) fn expire_rules(&mut self, now: u64) -> Option<String> {
        let ids = self.rules.expired(now);
        if ids.is_empty() {
            return None;
        }
        Some(self.change_rules(|r| {
            let gone: Vec<String> = ids.iter().filter_map(|id| r.remove(*id)).map(|rule| rule.to_string()).collect();
            Ok(format!("rule ended: {}", gone.join(", ")))
        }))
    }

    pub(crate) fn remove_rule(&mut self, id: u32) -> String {
        self.change_rules(|r| r.remove(id).map(|rule| format!("removed {rule}")).ok_or_else(|| "no such rule".into()))
    }

    /// Hit totals: the count before the last table rewrite plus the live
    /// table's counter. Slot = position in the list.
    pub(crate) fn refresh_hits(&mut self) {
        for (slot, r) in self.rules.rules.iter_mut().enumerate() {
            r.hits = r.hits_base + self.probe.rule_hits(slot);
        }
    }

    /// Reads the kernel's direction and verdict for every flow, while rules
    /// are in force.
    pub(crate) fn refresh_conns(&mut self) {
        let active = !self.rules.rules.is_empty() || self.rules.default != rules::Action::Allow;
        for f in self.collector.flows.values_mut() {
            f.conn = if active { self.probe.conn(&netmon_common::ConnKey::from_flow(&f.key)) } else { None };
        }
    }

    /// Edits the rules and writes the new table to the kernel. On any error
    /// the old rules stay, in userspace and in the kernel.
    pub(crate) fn change_rules(&mut self, edit: impl FnOnce(&mut Rules) -> Result<String, String>) -> String {
        // Positions change below: keep the hits counted so far.
        self.refresh_hits();
        for r in &mut self.rules.rules {
            r.hits_base = r.hits;
        }
        let old = self.rules.clone();
        let msg = match edit(&mut self.rules) {
            Ok(m) => m,
            // A failed edit can have changed some rules already (a rules
            // file that fails at its third rule): none of it stays.
            Err(e) => {
                self.rules = old;
                return e;
            }
        };
        match self.probe.set_rules(&self.rules.entries(), self.rules.exe_ids(), self.rules.default.kernel()) {
            Ok(()) => {
                let host_error = self.sync_host_blocks(Instant::now());
                if let Some(e) = self.sync_exe_blocks().or(host_error) {
                    return format!("{msg}; {e}");
                }
                msg
            }
            Err(e) => {
                self.rules = old;
                format!("rule update failed: {e:#}")
            }
        }
    }

    /// Appends the rules of the rules file. Returns a status message, or
    /// None when the default file does not exist. Any error loads no rule
    /// of the file.
    pub(crate) fn load_rules_file(&mut self, args: &Args) -> Result<Option<String>, String> {
        let path = args.rules.clone().unwrap_or_else(|| rulefile::DEFAULT_PATH.into());
        self.rules_path = path.clone();
        let fail = |e: String| Err(format!("rules file {}: {e}; no file rules loaded", path.display()));
        let text = match rulefile::read(&path, args.rules.is_some()) {
            Ok(Some(t)) => t,
            Ok(None) => return Ok(None),
            Err(e) => return fail(e),
        };
        let parsed = match rulefile::parse(&text) {
            Ok(p) => p,
            Err(e) => return fail(e),
        };
        // Rules that ended while the monitor did not run are left out.
        let now = rules::unix_now();
        let (rules_in, ended): (Vec<_>, Vec<_>) = parsed.rules.into_iter().partition(|r| r.until.is_none_or(|u| u > now));
        let n = rules_in.len();
        let hosts = parsed.hosts;
        let default = parsed.default;
        // A list that cannot be read is no error of the rules file: it
        // stays in the Hosts tab with its error, and a reload tries again.
        let mut left = crate::blocklist::MAX_NAMES;
        let lists: Vec<_> = parsed
            .blocklists
            .into_iter()
            .map(|l| {
                let names = read_blocklist(Path::new(&l.path), left);
                left -= names.as_ref().map_or(0, |(n, _)| n.len());
                (l, names)
            })
            .collect();
        let mut failed = false;
        let msg = self.change_rules(|rules| {
            if let Some(d) = default {
                rules.default = d;
            }
            for r in rules_in {
                let id = rules.insert(usize::MAX, r.action, r.m, &r.comment).map_err(|e| {
                    failed = true;
                    format!("line {}: {e}", r.line)
                })?;
                rules.set_until(id, r.until);
            }
            let h = hosts.len();
            for x in hosts {
                rules.add_host(&x.pattern, &x.comment).map_err(|e| {
                    failed = true;
                    format!("line {}: {e}", x.line)
                })?;
            }
            for (l, names) in lists {
                rules.add_blocklist(&l.path, &l.comment, names).map_err(|e| {
                    failed = true;
                    format!("line {}: {e}", l.line)
                })?;
            }
            let d = if rules.default == rules::Action::Allow { String::new() } else { format!(", default {}", rules.default) };
            let h = if h == 0 { String::new() } else { format!(", {h} blocked hosts") };
            let h = match rules.blocklists.len() {
                0 => h,
                n => format!("{h}, {n} blocklists ({} names)", rules.blocklist_names()),
            };
            let e = if ended.is_empty() { String::new() } else { format!(", {} ended rules left out", ended.len()) };
            Ok(format!("{n} rules from {}{d}{h}{e}", path.display()))
        });
        if failed || msg.starts_with("rule update failed") { fail(msg) } else { Ok(Some(msg)) }
    }

    /// Marks running processes of exes that rules name. The exec and fork
    /// tracepoints keep the marks current between refreshes; this catches
    /// processes that ran before the rule and any the tracepoints missed.
    /// Returns an error message if processes could not be marked: their
    /// exe rules then do not apply to them.
    pub(crate) fn sync_exe_blocks(&mut self) -> Option<String> {
        let exes = self.rules.exe_ids();
        if exes.is_empty() {
            return None;
        }
        let inode_error = self.probe.refresh_exe_inodes();
        let procs = procfs::process::all_processes().ok()?;
        let running = procs.flatten().filter_map(|p| Some((p.pid as u32, p.exe().ok()?.to_string_lossy().into_owned())));
        // /proc/<pid>/exe names the real file: a rule path through a
        // symlink (/usr/sbin is a link to /usr/bin on Arch) must match it.
        let exes = rules::with_real_paths(exes, |p| std::fs::canonicalize(p).ok());
        let mut lost = 0;
        for (id, pids) in rules::pids_by_exe(running, &exes) {
            lost += self.probe.mark_pids(id, &pids);
        }
        (lost > 0).then(|| format!("exe marks full: exe rules do not apply to {lost} processes")).or(inode_error)
    }
}

/// Reads a host block list file with the checks of the rules file (owner
/// root, not writable by group or others), at most `max` names.
pub(crate) fn read_blocklist(path: &Path, max: usize) -> Result<(HashSet<String>, usize), String> {
    let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if size > crate::blocklist::MAX_FILE_BYTES {
        return Err(format!("file larger than {} MB", crate::blocklist::MAX_FILE_BYTES / 1024 / 1024));
    }
    let text = rulefile::read(path, true)?.unwrap_or_default();
    crate::blocklist::parse(&text, max)
}
