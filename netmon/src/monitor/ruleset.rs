//! Rules: edits, the rules file, exe marks and the lockout guard.

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
    pub(crate) fn toggle_block(&mut self, target: BlockTarget) -> String {
        if let Some(rule) = self.rules.find_block(&target) {
            return self.remove_rule(rule.id);
        }
        let msg = format!("blocked {target} (until the monitor stops; b again or Rules tab to undo)");
        self.change_rules(|r| r.block(target).map(|_| msg))
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
                if let Some(e) = self.sync_exe_blocks() {
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
        let n = parsed.rules.len();
        let default = parsed.default;
        let mut failed = false;
        let msg = self.change_rules(|rules| {
            if let Some(d) = default {
                rules.default = d;
            }
            for r in parsed.rules {
                rules.insert(usize::MAX, r.action, r.m, &r.comment).map_err(|e| {
                    failed = true;
                    format!("line {}: {e}", r.line)
                })?;
            }
            let d = if rules.default == rules::Action::Allow { String::new() } else { format!(", default {}", rules.default) };
            Ok(format!("{n} rules from {}{d}", path.display()))
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
