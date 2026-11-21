//! Ask mode: questions from the kernel, answers from the UIs.

use super::*;

impl<K: Kernel> Monitor<K> {
    /// Reads new ask events and times out old questions. Called often, so
    /// a question shows before the first TCP retransmit (~1 s). Returns
    /// true if the questions changed.
    pub(crate) fn poll_asks(&mut self, now: Instant) -> bool {
        let mut events = Vec::new();
        self.probe.drain_asks(ASK_BATCH, |e| events.push(*e));
        // Traffic without a socket may be a container's: get its table,
        // once per connection the tables do not know yet. Retransmits send
        // the same event again.
        self.take_containers();
        let containers = &self.containers;
        let new: Vec<_> = events
            .iter()
            .filter(|e| e.tgid == 0 && !self.asks_tried.contains(&e.key) && container_of(containers, &e.key).is_none())
            .map(|e| e.key)
            .collect();
        if !new.is_empty() && self.refresh_containers(now, ASK_CONTAINER_REFRESH) {
            if self.asks_tried.len() > MAX_ASKS_TRIED {
                self.asks_tried.clear();
            }
            self.asks_tried.extend(new);
        }
        let mut changed = !events.is_empty();
        for ev in events {
            let (info, host) = self.prompt_for(&ev, now);
            // Events still in the ring when an answer made a rule: the rule
            // decides their next retransmit, so do not ask again.
            // The kernel asked because it could not match the rule yet (the
            // exe is not marked before the next /proc scan): write the
            // rule's verdict, or the connection would hang with no question.
            let dest = std::net::SocketAddr::new(ask::remote(&ev.key), ev.key.remote_port);
            if let Some(rule) = self.rules.first_match(ev.key.proto, dest, &info.exe, rules::Dir::Out) {
                let _ = self.probe.set_verdict(&ev.key, rule.action.kernel());
                continue;
            }
            if self.asks.add(ev.key, info, host) == ask::Added::Full {
                let _ = self.probe.set_verdict(&ev.key, netmon_common::ACTION_DENY);
            }
        }
        for p in self.asks.expired(now) {
            changed = true;
            for d in &p.dests {
                self.answer_conns(&d.conns, netmon_common::ACTION_DENY);
            }
        }
        // Container tables arrive a moment after the question: name the
        // container as soon as they do.
        // Unknown processes share one question until then: name it only if
        // all its connections belong to one container process.
        for p in self.asks.pending.iter_mut().filter(|p| p.pid == 0) {
            let owners: Vec<Option<Owner>> =
                p.dests.iter().flat_map(|d| &d.conns).map(|k| container_of(&self.containers, k)).collect();
            let label = |o: &Owner| format!("container:{}/{}", o.container.as_deref().unwrap_or("?"), o.comm);
            match owners.first() {
                Some(Some(first)) if owners.iter().all(|o| o.as_ref().is_some_and(|o| o.pid == first.pid)) => {
                    p.pid = first.pid;
                    p.comm = label(first);
                    changed = true;
                }
                _ if owners.iter().flatten().count() > 0 && p.comm != SEVERAL => {
                    p.comm = SEVERAL.into();
                    changed = true;
                }
                _ => {}
            }
        }
        changed
    }

    /// The asking process and the remote end's name. Traffic without a
    /// socket (pid 0) is looked up in the container tables: the question
    /// then names the container process, but keeps no exe, because the
    /// kernel cannot match exe rules on that traffic.
    pub(crate) fn prompt_for(&mut self, ev: &netmon_common::AskEvent, now: Instant) -> (ask::Prompt, Option<String>) {
        let container = match ev.tgid {
            0 => container_of(&self.containers, &ev.key),
            _ => None,
        };
        let pid = container.as_ref().map_or(ev.tgid, |o| o.pid);
        let comm = match &container {
            Some(o) => format!("container:{}/{}", o.container.as_deref().unwrap_or("?"), o.comm),
            None if pid == 0 => "unknown process".to_string(),
            None => std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|c| text::sanitize(c.trim()))
                .unwrap_or_else(|_| "exited process".into()),
        };
        let mut owner = Owner::new(pid, &comm);
        if pid != 0 {
            self.procs.fill(&mut owner, read_details);
        }
        let d = owner.details.unwrap_or_default();
        let info = ask::Prompt {
            id: 0,
            pid,
            comm,
            exe: if container.is_some() { String::new() } else { d.exe },
            user: d.user,
            dests: Vec::new(),
            since: now,
            selected: 0,
            scope: ask::Scope::Program,
        };
        (info, self.hosts.get(ask::remote(&ev.key), now).map(str::to_string))
    }

    /// Writes the verdict of waiting connections.
    pub(crate) fn answer_conns(&mut self, conns: &[netmon_common::ConnKey], action: u8) {
        for k in conns {
            let _ = self.probe.set_verdict(k, action);
        }
    }

    /// Answers question `question` for destination `dest`, with a rule of
    /// scope `scope` or once.
    pub(crate) fn answer(&mut self, question: u64, dest: DestId, scope: ask::Scope, a: Answer) -> String {
        let Some(qi) = self.asks.pending.iter().position(|p| p.id == question) else {
            return "question already answered or timed out".into();
        };
        let p = &mut self.asks.pending[qi];
        let Some(di) = p.dests.iter().position(|d| DestId::from(d) == dest)
        else {
            return "destination already answered".into();
        };
        p.selected = di;
        p.scope = scope;
        match a {
            Answer::Once { allow } => {
                let d = p.dests.remove(di);
                p.selected = p.selected.min(p.dests.len().saturating_sub(1));
                let comm = p.comm.clone();
                if p.dests.is_empty() {
                    self.asks.pending.remove(qi);
                }
                let action = if allow { netmon_common::ACTION_ALLOW } else { netmon_common::ACTION_DENY };
                self.answer_conns(&d.conns, action);
                let target = d.host.unwrap_or_else(|| d.remote.to_string());
                format!("{} {comm} to {target}:{} once", if allow { "allowed" } else { "denied" }, d.port)
            }
            Answer::Rule { allow, always } => {
                let Some(m) = p.rule_match() else {
                    return "process unknown: pick port or destination scope with ←→, or o/x for once".into();
                };
                let action = if allow { rules::Action::Allow } else { rules::Action::Deny };
                let label = format!("{action} {m}");
                let msg = self.change_rules(|r| {
                    let id = r.insert(0, action, m, "asked")?;
                    if !always {
                        r.set_temporary(id);
                    }
                    Ok(format!("{label} ({})", if always { "always; s in Rules saves it" } else { "until the monitor stops" }))
                });
                self.drop_decided_asks();
                msg
            }
        }
    }

    /// Drops the waiting destinations a rule now decides. The rule change
    /// made the kernel decide them again: their next retransmit follows
    /// the rule.
    pub(crate) fn drop_decided_asks(&mut self) {
        let rules = &self.rules;
        for p in self.asks.pending.iter_mut() {
            let exe = p.exe.clone();
            p.drop_decided(|d| {
                rules.first_match(d.proto, std::net::SocketAddr::new(d.remote, d.port), &exe, rules::Dir::Out).is_some()
            });
        }
        self.asks.pending.retain(|p| !p.dests.is_empty());
    }
}
