mod app;
mod ask;
mod capture;
mod collector;
mod decode;
mod ifaces;
mod linkwatch;
mod names;
mod netns;
mod probe;
mod procmap;
mod rulefile;
mod rules;
mod text;
mod ui;

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use anyhow::Context as _;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::{
    app::{Action, App, Key, Tab, human},
    capture::{Capture, Captured, Target},
    collector::Collector,
    ifaces::Names,
    linkwatch::LinkWatch,
    probe::{Kernel, Probe},
    procmap::{Listeners, Owner, OwnerCache, ProcCache, SocketTable, read_details},
    rules::{BlockTarget, Rules, guard_endpoints},
};

/// Live view of network connections: owning process, interface and traffic.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Refresh interval in milliseconds.
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,
    /// Drop flows idle for this many seconds.
    #[arg(long, default_value_t = 30)]
    expire_secs: u64,
    /// Sample for N seconds, print the connections once and exit (no TUI).
    #[arg(long, value_name = "SECONDS")]
    once: Option<u64>,
    /// Rules file. Must belong to root and not be writable by group or
    /// others. [default: /etc/netmon/rules.toml, skipped if missing]
    #[arg(long, value_name = "PATH")]
    rules: Option<std::path::PathBuf>,
    /// Ask about outbound connections no rule decides (default action
    /// "ask"); unmatched inbound connections are denied.
    #[arg(long)]
    ask: bool,
}

impl Args {
    /// Refresh interval, at least 100 ms.
    fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms.max(100))
    }

    /// Idle ticks before a flow expires, from the clamped interval.
    fn expire_ticks(&self) -> u32 {
        let ms = self.interval().as_millis() as u64;
        (self.expire_secs.saturating_mul(1000) / ms).clamp(1, u32::MAX as u64) as u32
    }
}

/// How often captured packets are read while a capture runs.
const CAPTURE_POLL: Duration = Duration::from_millis(50);
/// Max packets taken from the ring buffer per poll, so the UI stays responsive.
const DRAIN_BATCH: usize = 4_096;
/// The container process behind a connection without a socket on the
/// host, by remote end and local port.
fn container_of(tables: &[procmap::ContainerTable], key: &netmon_common::ConnKey) -> Option<Owner> {
    let remote = std::net::SocketAddr::new(ask::remote(key), key.remote_port);
    let any_local = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), key.local_port);
    tables.iter().find_map(|t| t.lookup(key.proto, any_local, remote)).map(|(o, _)| o.clone())
}

/// Reads container socket tables in a thread: one read takes 150-250 ms on
/// a host with 30 namespaces, too long for the UI loop. Each `()` sent asks
/// for one read; the tables come back on the other channel.
fn container_reader() -> (std::sync::mpsc::SyncSender<()>, std::sync::mpsc::Receiver<Vec<procmap::ContainerTable>>) {
    let (req_tx, req_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (res_tx, res_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut owners = OwnerCache::default();
        let mut namespaces = Vec::new();
        let mut scanned: Option<Instant> = None;
        // Ends when the Monitor (the sender) is dropped.
        while req_rx.recv().is_ok() {
            if scanned.is_none_or(|t| t.elapsed() >= NETNS_RESCAN) {
                namespaces = netns::scan();
                scanned = Some(Instant::now());
            }
            if res_tx.send(procmap::read_containers(&mut owners, &namespaces)).is_err() {
                break;
            }
        }
    });
    (req_tx, res_rx)
}

/// How often container socket tables are reread while flows lack owners.
const CONTAINER_REFRESH: Duration = Duration::from_secs(3);
/// How often the list of network namespaces is rescanned.
const NETNS_RESCAN: Duration = Duration::from_secs(10);
/// Most ask events read per poll.
const ASK_BATCH: usize = 256;
/// ClientHello first segments waiting for their second one.
const MAX_HELLO_PARTS: usize = 256;
/// Most name events read per refresh; the rest wait in the ring.
const NAME_BATCH: usize = 4_096;
/// How often the TUI loop checks for interface events between ticks.
const LINK_POLL: Duration = Duration::from_millis(200);

/// The main loop's state. Generic over the kernel side so tests can run it
/// with a fake.
struct Monitor<K: Kernel = Probe> {
    probe: K,
    collector: Collector,
    names: Names,
    last: Instant,
    ticks: u64,
    capture: Option<Capture>,
    /// Copy of the collector shown while paused. Counting goes on behind it,
    /// so rates are right again after resume.
    frozen: Option<Collector>,
    owners: OwnerCache,
    procs: ProcCache,
    rules: Rules,
    /// Interface events. None: fall back to a rescan every 2 ticks.
    links: Option<LinkWatch>,
    /// Where `s` in the Rules tab saves.
    rules_path: std::path::PathBuf,
    /// Hostnames from DNS answers.
    hosts: names::HostNames,
    /// Ask mode: questions waiting for the user.
    asks: ask::Asks,
    /// Their socket tables, read when needed (see refresh_containers).
    containers: Vec<procmap::ContainerTable>,
    containers_asked: Option<Instant>,
    containers_tx: std::sync::mpsc::SyncSender<()>,
    containers_rx: std::sync::mpsc::Receiver<Vec<procmap::ContainerTable>>,
    /// TLS server name per connection, from its ClientHello.
    sni: HashMap<netmon_common::FlowKey, String>,
    /// First segments of ClientHellos that continue in the next segment.
    hello_parts: HashMap<netmon_common::FlowKey, Vec<u8>>,
}

impl Monitor {
    fn new(args: &Args) -> anyhow::Result<(Self, Vec<String>)> {
        let mut probe = Probe::load()?;
        let hook_errors = probe.hook_errors.clone();
        let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        probe.set_guard(&guard_endpoints(ssh_connection().as_deref(), &resolv))?;
        let (mut mon, mut errors) = Monitor::with_kernel(probe, args)?;
        errors.extend(hook_errors);
        if let Some(msg) = mon.load_rules_file(args) {
            errors.push(msg);
        }
        if args.ask {
            let msg = mon.change_rules(|r| {
                r.default = rules::Action::Ask;
                Ok(String::new())
            });
            if !msg.is_empty() {
                errors.push(msg);
            }
        }
        match LinkWatch::open() {
            Ok(w) => mon.links = Some(w),
            Err(e) => errors.push(format!("interface events off, polling instead: {e}")),
        }
        Ok((mon, errors))
    }
}

impl<K: Kernel> Monitor<K> {
    fn with_kernel(mut probe: K, args: &Args) -> anyhow::Result<(Self, Vec<String>)> {
        let ifs = ifaces::list();
        let errors = probe.attach_new(&ifs);
        if probe.attached_count() == 0 {
            anyhow::bail!("could not attach to any interface: {}", errors.join("; "));
        }
        let mut names = Names::default();
        names.update(&ifs);
        let mut collector = Collector::new(args.expire_ticks());
        collector.counted = names.physical();
        let (containers_tx, containers_rx) = container_reader();
        let mon = Monitor { probe, collector, names, last: Instant::now(), ticks: 0, capture: None, frozen: None, owners: OwnerCache::default(), procs: ProcCache::default(), rules: Rules::default(), links: None, rules_path: rulefile::DEFAULT_PATH.into(), hosts: Default::default(), asks: Default::default(), containers: Vec::new(), containers_asked: None, containers_tx, containers_rx, sni: HashMap::new(), hello_parts: HashMap::new() };
        Ok((mon, errors))
    }

    /// What the UI shows: the frozen copy while paused, else live data.
    fn view(&self) -> &Collector {
        self.frozen.as_ref().unwrap_or(&self.collector)
    }

    /// Freezes or unfreezes the view to match the pause state.
    fn set_paused(&mut self, paused: bool) {
        if paused != self.frozen.is_some() {
            self.frozen = paused.then(|| self.collector.clone());
        }
    }

    /// Reads the counters, refreshes owners and attaches to new interfaces.
    fn tick(&mut self) -> Vec<String> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&mut self, now: Instant) -> Vec<String> {
        let mut errors = match self.links {
            Some(_) => self.check_links(),
            // No interface events: hot-plug check every 2 ticks.
            None if self.ticks.is_multiple_of(2) => self.rescan_ifaces(),
            None => Vec::new(),
        };
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        let expired = self.collector.ingest(self.probe.snapshot(), dt);
        self.probe.forget(&expired);
        let listeners = Listeners::build(
            self.probe.listeners().into_iter().map(|(proto, a, o)| (proto, a, Owner::from_kernel(&o))),
        );
        let table = SocketTable::read(&mut self.owners);
        // Container tables only when a flow still lacks a good owner.
        let unowned = self
            .collector
            .flows
            .values()
            .any(|f| f.owner_source <= collector::OwnerSource::Container && f.key.ifindex != netmon_common::LOOPBACK_IFINDEX);
        if unowned {
            self.refresh_containers(now, CONTAINER_REFRESH);
        }
        let probe = &self.probe;
        let kernel = |cookie| probe.sock_owner(cookie).map(|o| Owner::from_kernel(&o));
        self.collector.resolve(&table, &self.containers, &listeners, kernel);
        self.procs.prune(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists());
        for o in self.collector.flows.values_mut().filter_map(|f| f.owner.as_mut()) {
            self.procs.fill(o, read_details);
        }
        self.sync_exe_blocks();
        self.refresh_hits();
        self.refresh_conns();
        self.refresh_hosts(now);
        self.ticks += 1;
        if let Err(e) = self.sync_process_capture() {
            errors.push(format!("capture: {e:#}"));
        }
        errors
    }

    /// Attaches to interfaces that appeared since the last check.
    fn check_links(&mut self) -> Vec<String> {
        if self.links.as_ref().is_some_and(|l| l.changed()) { self.rescan_ifaces() } else { Vec::new() }
    }

    fn rescan_ifaces(&mut self) -> Vec<String> {
        let ifs = ifaces::list();
        self.names.update(&ifs);
        self.collector.counted = self.names.physical();
        self.probe.attach_new(&ifs)
    }

    /// A process capture follows the process: new flows join, closed ones leave.
    fn sync_process_capture(&mut self) -> anyhow::Result<()> {
        let Some(Capture { target: Target::Process { pid, .. }, running: true, .. }) = &self.capture else {
            return Ok(());
        };
        let keys = self.process_flows(*pid);
        self.probe.capture_flows(&keys)
    }

    fn process_flows(&self, pid: u32) -> HashSet<netmon_common::FlowKey> {
        self.collector
            .flows
            .values()
            .filter(|f| f.owner.as_ref().is_some_and(|o| o.pid == pid))
            .map(|f| f.key)
            .collect()
    }

    fn start_capture(&mut self, target: Target) -> anyhow::Result<()> {
        self.probe.capture_off()?;
        // Packets still queued belong to the old capture.
        self.probe.discard_packets();
        let mut cap = Capture::new(target);
        cap.drop_base = self.probe.capture_drops();
        let target = &cap.target;
        match target {
            Target::Interface { index, .. } => self.probe.capture_iface(*index)?,
            Target::Process { pid, .. } => self.probe.capture_flows(&self.process_flows(*pid))?,
            Target::Connection { key, .. } => self.probe.capture_flows(&HashSet::from([*key]))?,
        }
        self.capture = Some(cap);
        Ok(())
    }

    /// Moves up to `max` packets from the ring into the capture and updates
    /// its drop count.
    fn drain_capture(&mut self, max: usize) {
        let Some(cap) = self.capture.as_mut().filter(|c| c.running) else { return };
        let offset = cap.mono_to_wall;
        self.probe.drain_packets(max, |ev| cap.push(Captured::from_event(ev, offset)));
        cap.dropped = self.probe.capture_drops().saturating_sub(cap.drop_base);
    }

    /// Turns the selected row of a tab into a capture target.
    fn target_for(&self, app: &App, tab: Tab) -> Result<Target, String> {
        // Rows as the user sees them, so a paused view picks the shown row.
        let c = self.view();
        match tab {
            Tab::Interfaces => {
                let rows = app.iface_rows(c, &self.names);
                let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
                let r = app.selected_in(&ids).map(|i| &rows[i]).ok_or("no interface selected")?;
                Ok(Target::Interface { index: r.index, name: r.name.clone() })
            }
            Tab::Processes => {
                let rows = app.proc_rows(c, &self.names);
                let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
                let r = app.selected_in(&ids).map(|i| &rows[i]).ok_or("no process selected")?;
                let pid = r.pid_num.ok_or("owner unknown: capture its connections instead")?;
                Ok(Target::Process { pid, comm: r.process.clone() })
            }
            Tab::Connections => {
                let rows = app.conn_rows(c, &self.names);
                let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
                let r = app.selected_in(&ids).map(|i| &rows[i]).ok_or("no connection selected")?;
                Ok(Target::Connection {
                    key: r.key,
                    label: format!("{} {} → {} on {}", r.proto, r.local, r.remote, r.iface),
                })
            }
            Tab::Capture | Tab::Rules => Err("select a row in another tab".into()),
        }
    }

    /// Adds the rule, or removes it if it exists.
    fn toggle_block(&mut self, target: BlockTarget) -> String {
        if let Some(rule) = self.rules.find_block(&target) {
            return self.remove_rule(rule.id);
        }
        let msg = format!("blocked {target} (until netmon exits; b again or Rules tab to undo)");
        self.change_rules(|r| r.block(target).map(|_| msg))
    }

    fn remove_rule(&mut self, id: u32) -> String {
        self.change_rules(|r| r.remove(id).map(|rule| format!("removed {rule}")).ok_or_else(|| "no such rule".into()))
    }

    /// Hit totals: the count before the last table rewrite plus the live
    /// table's counter. Slot = position in the list.
    fn refresh_hits(&mut self) {
        for (slot, r) in self.rules.rules.iter_mut().enumerate() {
            r.hits = r.hits_base + self.probe.rule_hits(slot);
        }
    }

    /// Asks the container reader for fresh tables if the last request is
    /// older than `max_age`, and takes any tables it has finished.
    fn refresh_containers(&mut self, now: Instant, max_age: Duration) {
        while let Ok(tables) = self.containers_rx.try_recv() {
            self.containers = tables;
        }
        if self.containers_asked.is_some_and(|t| now.duration_since(t) < max_age) {
            return;
        }
        // The reader is busy with the previous request if it is still
        // queued; asking twice only repeats the work.
        let _ = self.containers_tx.try_send(());
        self.containers_asked = Some(now);
    }

    /// Reads new ask events and times out old questions. Called often, so
    /// a question shows before the first TCP retransmit (~1 s).
    fn poll_asks(&mut self, now: Instant) {
        let mut events = Vec::new();
        self.probe.drain_asks(ASK_BATCH, |e| events.push(*e));
        // Traffic without a socket may be a container's: get its table.
        if events.iter().any(|e| e.tgid == 0) {
            self.refresh_containers(now, Duration::from_secs(1));
        }
        for ev in events {
            let (info, host) = self.prompt_for(&ev, now);
            // Events still in the ring when an answer made a rule: the rule
            // decides their next retransmit, so do not ask again.
            let dest = std::net::SocketAddr::new(ask::remote(&ev.key), ev.key.remote_port);
            if self.rules.first_match(ev.key.proto, dest, &info.exe, rules::Dir::Out).is_some() {
                continue;
            }
            if self.asks.add(ev.key, info, host) == ask::Added::Full {
                let _ = self.probe.set_verdict(&ev.key, netmon_common::ACTION_DENY);
            }
        }
        for p in self.asks.expired(now) {
            for d in &p.dests {
                self.answer_conns(&d.conns, netmon_common::ACTION_DENY);
            }
        }
        // Container tables arrive a moment after the question: name the
        // container as soon as they do.
        for p in self.asks.pending.iter_mut().filter(|p| p.pid == 0) {
            let Some(k) = p.dests.iter().flat_map(|d| &d.conns).next() else { continue };
            if let Some(o) = container_of(&self.containers, k) {
                p.pid = o.pid;
                p.comm = format!("container:{}/{}", o.container.as_deref().unwrap_or("?"), o.comm);
            }
        }
    }

    /// The asking process and the remote end's name. Traffic without a
    /// socket (pid 0) is looked up in the container tables: the question
    /// then names the container process, but keeps no exe, because the
    /// kernel cannot match exe rules on that traffic.
    fn prompt_for(&mut self, ev: &netmon_common::AskEvent, now: Instant) -> (ask::Prompt, Option<String>) {
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
    fn answer_conns(&mut self, conns: &[netmon_common::ConnKey], action: u8) {
        for k in conns {
            let _ = self.probe.set_verdict(k, action);
        }
    }

    /// Answers the shown question.
    fn answer(&mut self, a: crate::app::Answer) -> String {
        use crate::app::Answer;
        let Some(p) = self.asks.pending.front_mut() else { return String::new() };
        match a {
            Answer::Once { allow } => {
                let Some(d) = (p.selected < p.dests.len()).then(|| p.dests.remove(p.selected)) else {
                    return String::new();
                };
                p.selected = p.selected.min(p.dests.len().saturating_sub(1));
                let comm = p.comm.clone();
                if p.dests.is_empty() {
                    self.asks.pending.pop_front();
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
                    Ok(format!("{label} ({})", if always { "always; s in Rules saves it" } else { "until netmon exits" }))
                });
                self.drop_decided_asks();
                msg
            }
        }
    }

    /// Drops the waiting destinations a rule now decides. The rule change
    /// made the kernel decide them again: their next retransmit follows
    /// the rule.
    fn drop_decided_asks(&mut self) {
        let rules = &self.rules;
        for p in self.asks.pending.iter_mut() {
            let exe = p.exe.clone();
            p.drop_decided(|d| {
                rules.first_match(d.proto, std::net::SocketAddr::new(d.remote, d.port), &exe, rules::Dir::Out).is_some()
            });
        }
        self.asks.pending.retain(|p| !p.dests.is_empty());
    }

    /// Reads new DNS answers and ClientHellos and names every flow's
    /// remote end. The TLS server name wins: it is what the client asked
    /// this server for, while one address can serve many DNS names.
    fn refresh_hosts(&mut self, now: Instant) {
        let (hosts, sni, parts) = (&mut self.hosts, &mut self.sni, &mut self.hello_parts);
        self.probe.drain_names(NAME_BATCH, |ev| {
            let data = &ev.data[..(ev.len as usize).min(ev.data.len())];
            match ev.kind {
                netmon_common::NAME_DNS => {
                    for (ip, name, _ttl) in names::dns_answers(data) {
                        hosts.insert(ip, name, now);
                    }
                }
                netmon_common::NAME_TLS => match names::client_hello_sni(data) {
                    Some(name) => {
                        sni.insert(ev.key, name);
                    }
                    None if names::record_continues(data) => {
                        if parts.len() >= MAX_HELLO_PARTS {
                            parts.clear();
                        }
                        parts.insert(ev.key, data.to_vec());
                    }
                    None => {}
                },
                netmon_common::NAME_TLS_CONT => {
                    if let Some(mut hello) = parts.remove(&ev.key) {
                        hello.extend_from_slice(data);
                        if let Some(name) = names::client_hello_sni(&hello) {
                            sni.insert(ev.key, name);
                        }
                    }
                }
                _ => {}
            }
        });
        // Names of connections that are gone.
        let flows = &self.collector.flows;
        self.sni.retain(|k, _| flows.contains_key(k));
        self.hello_parts.retain(|k, _| flows.contains_key(k));
        for (k, f) in self.collector.flows.iter_mut() {
            // Dual-stack sockets show IPv4 peers as ::ffff:a.b.c.d.
            let ip = procmap::normalize(f.remote).ip();
            (f.host, f.host_source) = match (self.sni.get(k), self.hosts.get(ip, now)) {
                (Some(n), _) => (Some(n.clone()), "tls"),
                (None, Some(n)) => (Some(n.to_string()), "dns"),
                (None, None) => (None, ""),
            };
        }
    }

    /// Reads the kernel's direction and verdict for every flow, while rules
    /// are in force.
    fn refresh_conns(&mut self) {
        let active = !self.rules.rules.is_empty() || self.rules.default != rules::Action::Allow;
        for f in self.collector.flows.values_mut() {
            f.conn = if active { self.probe.conn(&netmon_common::ConnKey::from_flow(&f.key)) } else { None };
        }
    }

    /// Edits the rules and writes the new table to the kernel. On any error
    /// the old rules stay, in userspace and in the kernel.
    fn change_rules(&mut self, edit: impl FnOnce(&mut Rules) -> Result<String, String>) -> String {
        // Positions change below: keep the hits counted so far.
        self.refresh_hits();
        for r in &mut self.rules.rules {
            r.hits_base = r.hits;
        }
        let old = self.rules.clone();
        let msg = match edit(&mut self.rules) {
            Ok(m) => m,
            Err(e) => return e,
        };
        match self.probe.set_rules(&self.rules.entries(), self.rules.exe_ids(), self.rules.default.kernel()) {
            Ok(()) => {
                self.sync_exe_blocks();
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
    fn load_rules_file(&mut self, args: &Args) -> Option<String> {
        let path = args.rules.clone().unwrap_or_else(|| rulefile::DEFAULT_PATH.into());
        self.rules_path = path.clone();
        let fail = |e: String| Some(format!("rules file {}: {e}; no file rules loaded", path.display()));
        let text = match rulefile::read(&path, args.rules.is_some()) {
            Ok(Some(t)) => t,
            Ok(None) => return None,
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
        if failed || msg.starts_with("rule update failed") { fail(msg) } else { Some(msg) }
    }

    /// Marks running processes of exes that rules name. The exec and fork
    /// tracepoints keep the marks current between refreshes; this catches
    /// processes that ran before the rule and any the tracepoints missed.
    fn sync_exe_blocks(&mut self) {
        let exes = self.rules.exe_ids();
        if exes.is_empty() {
            return;
        }
        let Ok(procs) = procfs::process::all_processes() else { return };
        let running = procs.flatten().filter_map(|p| Some((p.pid as u32, p.exe().ok()?.to_string_lossy().into_owned())));
        for (id, pids) in rules::pids_by_exe(running, exes) {
            self.probe.mark_pids(id, &pids);
        }
    }

    /// The selected connection in the Connections tab.
    fn selected_conn(&self, app: &App) -> Option<crate::app::ConnRow> {
        let rows = app.conn_rows(self.view(), &self.names);
        let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
        let i = app.selected_in(&ids)?;
        rows.into_iter().nth(i)
    }

    fn handle(&mut self, app: &mut App, action: Action) {
        match action {
            Action::StartCapture(tab) => match self.target_for(app, tab) {
                Ok(target) => match self.start_capture(target) {
                    Ok(()) => {
                        app.tab = Tab::Capture;
                        app.status.clear();
                    }
                    Err(e) => app.status = format!("capture failed: {e:#}"),
                },
                Err(e) => app.status = e,
            },
            Action::StopCapture => {
                if let Err(e) = self.probe.capture_off() {
                    app.status = format!("stop failed: {e:#}");
                }
                // Keep what the kernel already captured. The ring holds at
                // most CAPTURE_RING_BYTES, so this ends.
                self.drain_capture(usize::MAX);
                // Packets stay for viewing and saving until the next capture.
                if let Some(cap) = self.capture.as_mut() {
                    cap.running = false;
                    app.status = format!("capture stopped, {} packets kept", cap.packets.len());
                }
            }
            Action::SavePcap => match &self.capture {
                Some(cap) if !cap.packets.is_empty() => {
                    let dir = std::env::current_dir().unwrap_or_else(|_| ".".into());
                    app.status = match capture::save(cap, &dir) {
                        Ok(path) => format!("saved {} packets to {}", cap.packets.len(), path.display()),
                        Err(e) => format!("save failed: {e}"),
                    };
                }
                _ => app.status = "nothing to save".into(),
            },
            Action::ClearCapture => {
                if let Some(cap) = self.capture.as_mut() {
                    cap.clear();
                }
            }
            Action::MovePacket(d) => {
                if let Some(cap) = self.capture.as_mut() {
                    cap.select(d);
                }
            }
            Action::ToggleBlockRemote => {
                app.status = match self.selected_conn(app) {
                    Some(r) => {
                        let remote = collector::addr(r.key.family, &r.key.remote_addr, r.key.remote_port);
                        self.toggle_block(BlockTarget::host(remote.ip()))
                    }
                    None => "no connection selected".into(),
                };
            }
            Action::ToggleBlockPort => {
                app.status = match self.selected_conn(app) {
                    Some(r) if r.key.remote_port != 0 => self.toggle_block(BlockTarget::Port(r.key.proto, r.key.remote_port)),
                    Some(_) => "this connection has no port".into(),
                    None => "no connection selected".into(),
                };
            }
            Action::ToggleBlockProcess => {
                let rows = app.proc_rows(self.view(), &self.names);
                let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
                app.status = match app.selected_in(&ids).map(|i| &rows[i]) {
                    Some(r) if !r.exe.is_empty() => self.toggle_block(BlockTarget::Exe(r.exe.clone())),
                    Some(_) => "exe unknown for this process: block its remote address instead".into(),
                    None => "no process selected".into(),
                };
            }
            Action::Answer(a) => app.status = self.answer(a),
            Action::AskSelect(step) => {
                if let Some(p) = self.asks.pending.front_mut() {
                    p.move_selection(step);
                }
            }
            Action::AskScope(step) => {
                if let Some(p) = self.asks.pending.front_mut() {
                    p.scope = p.scope.step(step);
                }
            }
            Action::SaveRules => {
                let path = &self.rules_path;
                app.status = match rulefile::save(path, &rulefile::render(&self.rules)) {
                    Ok(()) => format!("saved {} rules to {}", self.rules.rules.len(), path.display()),
                    Err(e) => format!("save {} failed: {e}", path.display()),
                };
            }
            Action::RemoveRule => {
                let ids: Vec<_> = self.rules.rules.iter().map(|r| crate::app::RowId::Rule(r.id)).collect();
                app.status = match app.selected_in(&ids).map(|i| self.rules.rules[i].id) {
                    Some(id) => self.remove_rule(id),
                    None => "no rule selected".into(),
                };
            }
            Action::JumpPacket(newest) => {
                if let Some(cap) = self.capture.as_mut() {
                    cap.select(if newest { isize::MAX / 2 } else { isize::MIN / 2 });
                }
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let (mut mon, errors) = Monitor::new(&args)?;
    for e in &errors {
        eprintln!("warning: {e}");
    }
    match args.once {
        Some(secs) => print_once(&mut mon, secs),
        None => run_tui(&mut mon, &args, errors.join("; ")),
    }
}

fn print_once(mon: &mut Monitor, secs: u64) -> anyhow::Result<()> {
    mon.tick();
    std::thread::sleep(Duration::from_secs(secs.max(1)));
    mon.tick();
    let rows = App::default().conn_rows(&mon.collector, &mon.names);
    println!(
        "{:<16} {:>7} {:<5} {:<40} {:<40} {:<12} {:<10} {:>10} {:>10} {:>8}",
        "PROCESS", "PID", "PROTO", "LOCAL", "REMOTE", "IFACE", "STATE", "UP/s", "DOWN/s", "TOTAL"
    );
    for r in rows {
        println!(
            "{:<16} {:>7} {:<5} {:<40} {:<40} {:<12} {:<10} {:>10} {:>10} {:>8}",
            r.process, r.pid, r.proto, r.local, r.remote, r.iface, r.state,
            human(r.tx_rate), human(r.rx_rate), human(r.total as f64)
        );
    }
    Ok(())
}

fn run_tui(mon: &mut Monitor, args: &Args, status: String) -> anyhow::Result<()> {
    let interval = args.interval();
    let mut app = App { interval_secs: interval.as_secs_f64(), status, ..App::default() };
    let mut terminal = ratatui::init();
    let result = (|| -> anyhow::Result<()> {
        mon.tick();
        let mut next = Instant::now() + interval;
        while !app.quit {
            terminal.draw(|f| ui::draw(f, &mut app, mon.view(), &mon.names, mon.capture.as_ref(), &mon.rules))?;
            let mut timeout = next.saturating_duration_since(Instant::now());
            if mon.capture.as_ref().is_some_and(|c| c.running) {
                timeout = timeout.min(CAPTURE_POLL);
            }
            if mon.links.is_some() || mon.rules.default == rules::Action::Ask {
                timeout = timeout.min(LINK_POLL);
            }
            if event::poll(timeout).context("poll terminal events")?
                && let Event::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
                && let Some(key) = map_key(k)
                && let Some(action) = app.on_key(key)
            {
                mon.handle(&mut app, action);
            }
            mon.set_paused(app.paused);
            mon.drain_capture(DRAIN_BATCH);
            mon.poll_asks(Instant::now());
            app.ask = mon.asks.pending.front().map(|p| (p.clone(), mon.asks.pending.len() - 1));
            if let Some(e) = mon.check_links().first() {
                app.status = e.clone();
            }
            if Instant::now() >= next {
                next += interval;
                let errs = mon.tick();
                if let Some(e) = errs.first() {
                    app.status = e.clone();
                }
            }
        }
        Ok(())
    })();
    ratatui::restore();
    result
}

/// SSH_CONNECTION of the session netmon runs in. sudo usually drops it from
/// the environment, so the parent processes (the shell, sshd's child) are
/// asked too.
fn ssh_connection() -> Option<String> {
    if let Ok(v) = std::env::var("SSH_CONNECTION") {
        return Some(v);
    }
    let mut pid = std::process::id() as i32;
    for _ in 0..16 {
        let p = procfs::process::Process::new(pid).ok()?;
        if let Ok(env) = p.environ()
            && let Some(v) = env.get(std::ffi::OsStr::new("SSH_CONNECTION"))
        {
            return Some(v.to_string_lossy().into_owned());
        }
        pid = p.stat().ok()?.ppid;
        if pid <= 1 {
            return None;
        }
    }
    None
}

fn map_key(k: KeyEvent) -> Option<Key> {
    // Raw mode turns Ctrl-C into a key press; treat it as quit.
    if k.modifiers.contains(KeyModifiers::CONTROL) {
        return (k.code == KeyCode::Char('c')).then_some(Key::Char('q'));
    }
    Some(match k.code {
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Tab => Key::Tab,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(interval_ms: u64, expire_secs: u64) -> Args {
        Args { interval_ms, expire_secs, once: None, rules: None, ask: false }
    }

    #[test]
    fn expiry_uses_clamped_interval() {
        assert_eq!(args(1000, 30).expire_ticks(), 30);
        // 10 ms is clamped to 100 ms: 30 s are 300 ticks, not 3000.
        assert_eq!(args(10, 30).expire_ticks(), 300);
        assert_eq!(args(5000, 1).expire_ticks(), 1);
        assert_eq!(args(0, 30).interval(), Duration::from_millis(100));
    }

    use std::collections::VecDeque;

    use netmon_common::{CAPTURE_LEN, FlowStats, IPPROTO_TCP, PacketEvent, RULE_EXE, RULE_NET, RULE_PORT, RULE_PROTO, RuleEntry};

    use crate::ifaces::Iface;

    #[derive(Debug, PartialEq)]
    enum Mode {
        Off,
        Iface(u32),
        Flows(HashSet<netmon_common::FlowKey>),
    }

    /// Kernel stand-in: counters and a packet ring set by the test.
    struct Fake {
        flows: Vec<(netmon_common::FlowKey, FlowStats)>,
        ring: VecDeque<PacketEvent>,
        mode: Mode,
        drops: u64,
        table: Vec<RuleEntry>,
        exe_ids: std::collections::BTreeMap<String, u32>,
        default: u8,
        conns: HashMap<netmon_common::ConnKey, netmon_common::ConnState>,
        names: VecDeque<netmon_common::NameEvent>,
        asks: VecDeque<netmon_common::AskEvent>,
        verdicts: Vec<(netmon_common::ConnKey, u8)>,
        fail_block: bool,
        marked: Vec<(u32, u32)>,
    }

    impl Kernel for Fake {
        fn attach_new(&mut self, _: &[Iface]) -> Vec<String> {
            Vec::new()
        }
        fn attached_count(&self) -> usize {
            1
        }
        fn snapshot(&self) -> Vec<(netmon_common::FlowKey, FlowStats)> {
            self.flows.clone()
        }
        fn capture_iface(&mut self, ifindex: u32) -> anyhow::Result<()> {
            self.mode = Mode::Iface(ifindex);
            Ok(())
        }
        fn capture_flows(&mut self, keys: &HashSet<netmon_common::FlowKey>) -> anyhow::Result<()> {
            self.mode = Mode::Flows(keys.clone());
            Ok(())
        }
        fn capture_off(&mut self) -> anyhow::Result<()> {
            self.mode = Mode::Off;
            Ok(())
        }
        fn discard_packets(&mut self) {
            self.ring.clear();
        }
        fn drain_packets(&mut self, max: usize, mut f: impl FnMut(&PacketEvent)) {
            for _ in 0..max {
                let Some(ev) = self.ring.pop_front() else { break };
                f(&ev);
            }
        }
        fn capture_drops(&self) -> u64 {
            self.drops
        }
        fn forget(&mut self, keys: &[netmon_common::FlowKey]) {
            self.flows.retain(|(k, _)| !keys.contains(k));
        }
        fn sock_owner(&self, _: u64) -> Option<netmon_common::SockOwner> {
            None
        }
        fn listeners(&self) -> Vec<(u8, std::net::SocketAddr, netmon_common::SockOwner)> {
            Vec::new()
        }
        fn set_rules(
            &mut self,
            rules: &[RuleEntry],
            exe_ids: &std::collections::BTreeMap<String, u32>,
            default: u8,
        ) -> anyhow::Result<()> {
            if self.fail_block {
                anyhow::bail!("map full");
            }
            self.table = rules.to_vec();
            self.exe_ids = exe_ids.clone();
            self.default = default;
            Ok(())
        }
        fn conn(&self, key: &netmon_common::ConnKey) -> Option<netmon_common::ConnState> {
            self.conns.get(key).copied()
        }
        fn drain_asks(&mut self, max: usize, mut f: impl FnMut(&netmon_common::AskEvent)) {
            for _ in 0..max {
                let Some(ev) = self.asks.pop_front() else { break };
                f(&ev);
            }
        }
        fn set_verdict(&mut self, key: &netmon_common::ConnKey, action: u8) -> anyhow::Result<()> {
            self.verdicts.push((*key, action));
            Ok(())
        }
        fn drain_names(&mut self, max: usize, mut f: impl FnMut(&netmon_common::NameEvent)) {
            for _ in 0..max {
                let Some(ev) = self.names.pop_front() else { break };
                f(&ev);
            }
        }
        fn mark_pids(&mut self, id: u32, pids: &[u32]) {
            self.marked.extend(pids.iter().map(|p| (id, *p)));
        }
        fn rule_hits(&self, slot: usize) -> u64 {
            slot as u64 + 100
        }
        fn set_guard(&mut self, _: &[std::net::SocketAddr]) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn key(port: u16) -> netmon_common::FlowKey {
        // TEST-NET-2 addresses and high ports: no real socket matches them.
        let mut k = netmon_common::FlowKey {
            family: 4,
            proto: IPPROTO_TCP,
            local_port: port,
            remote_port: 443,
            ifindex: 2,
            ..Default::default()
        };
        k.local_addr[..4].copy_from_slice(&[198, 51, 100, 2]);
        k.remote_addr[..4].copy_from_slice(&[198, 51, 100, 9]);
        k
    }

    fn tx(bytes: u64) -> FlowStats {
        FlowStats { tx_bytes: bytes, ..Default::default() }
    }

    fn packet() -> PacketEvent {
        PacketEvent { ts_ns: 0, ifindex: 2, len: 0, cap_len: 0, ethertype: 0x0800, egress: 1, has_l2: 1, data: [0; CAPTURE_LEN] }
    }

    fn monitor() -> (Monitor<Fake>, Instant) {
        let fake = Fake {
            flows: Vec::new(),
            ring: VecDeque::new(),
            mode: Mode::Off,
            drops: 0,
            table: Vec::new(),
            exe_ids: Default::default(),
            default: 0,
            conns: HashMap::new(),
            names: VecDeque::new(),
            asks: VecDeque::new(),
            verdicts: Vec::new(),
            fail_block: false,
            marked: Vec::new(),
        };
        let (mut m, _) = Monitor::with_kernel(fake, &args(1000, 30)).unwrap();
        let t0 = Instant::now();
        m.last = t0;
        (m, t0)
    }

    fn secs(t0: Instant, s: u64) -> Instant {
        t0 + Duration::from_secs(s)
    }

    #[test]
    fn pause_freezes_view_and_keeps_rates_right() {
        let (mut m, t0) = monitor();
        m.probe.flows = vec![(key(50001), tx(0))];
        m.tick_at(secs(t0, 1));
        m.set_paused(true);
        m.probe.flows = vec![(key(50001), tx(1000))];
        m.tick_at(secs(t0, 2));
        assert_eq!(m.view().flows[&key(50001)].tx_rate, 0.0, "view frozen");
        assert_eq!(m.collector.flows[&key(50001)].tx_rate, 1000.0, "counting goes on");
        // 60 s paused, 1000 B/s all the time.
        for s in 3..=61 {
            m.probe.flows = vec![(key(50001), tx(1000 * (s - 1)))];
            m.tick_at(secs(t0, s));
        }
        m.set_paused(false);
        assert_eq!(m.view().flows[&key(50001)].tx_rate, 1000.0, "no spike after resume");
    }

    #[test]
    fn connection_capture_start_stop_and_restart() {
        let (mut m, t0) = monitor();
        m.probe.flows = vec![(key(50001), tx(10))];
        m.tick_at(secs(t0, 1));
        m.probe.drops = 5;
        let mut app = App::default();
        m.handle(&mut app, Action::StartCapture(Tab::Connections));
        assert_eq!(app.tab, Tab::Capture, "{}", app.status);
        assert_eq!(m.probe.mode, Mode::Flows(HashSet::from([key(50001)])));

        m.probe.ring.extend([packet(), packet()]);
        m.probe.drops = 7;
        m.drain_capture(DRAIN_BATCH);
        let cap = m.capture.as_ref().unwrap();
        assert_eq!((cap.packets.len(), cap.dropped), (2, 2), "drops count from capture start");

        // Stop keeps what is still queued in the ring.
        m.probe.ring.extend([packet(), packet(), packet()]);
        m.handle(&mut app, Action::StopCapture);
        let cap = m.capture.as_ref().unwrap();
        assert!(!cap.running);
        assert_eq!(cap.packets.len(), 5);
        assert_eq!(m.probe.mode, Mode::Off);

        // A stopped capture takes no more packets; a new one discards leftovers.
        m.probe.ring.push_back(packet());
        m.drain_capture(DRAIN_BATCH);
        assert_eq!(m.capture.as_ref().unwrap().packets.len(), 5);
        m.handle(&mut app, Action::StartCapture(Tab::Interfaces));
        assert_eq!(m.probe.mode, Mode::Iface(2));
        assert!(m.probe.ring.is_empty());
        assert_eq!(m.capture.as_ref().unwrap().packets.len(), 0);
    }

    #[test]
    fn process_capture_follows_new_flows_until_stopped() {
        let (mut m, t0) = monitor();
        let owner = Some(Owner::new(4242, "curl"));
        m.probe.flows = vec![(key(50001), tx(10))];
        m.tick_at(secs(t0, 1));
        m.collector.flows.get_mut(&key(50001)).unwrap().owner = owner.clone();
        m.start_capture(Target::Process { pid: 4242, comm: "curl".into() }).unwrap();
        assert_eq!(m.probe.mode, Mode::Flows(HashSet::from([key(50001)])));

        m.probe.flows.push((key(50002), tx(10)));
        m.tick_at(secs(t0, 2));
        m.collector.flows.get_mut(&key(50002)).unwrap().owner = owner;
        m.sync_process_capture().unwrap();
        assert_eq!(m.probe.mode, Mode::Flows(HashSet::from([key(50001), key(50002)])));

        let mut app = App::default();
        m.handle(&mut app, Action::StopCapture);
        m.tick_at(secs(t0, 3));
        assert_eq!(m.probe.mode, Mode::Off, "a stopped capture does not restart");
    }

    #[test]
    fn capture_needs_known_owner() {
        let (mut m, t0) = monitor();
        m.probe.flows = vec![(key(50001), tx(10))];
        m.tick_at(secs(t0, 1));
        let mut app = App { tab: Tab::Processes, ..App::default() };
        m.handle(&mut app, Action::StartCapture(Tab::Processes));
        assert!(app.status.contains("owner unknown"), "{}", app.status);
        assert!(m.capture.is_none());
    }

    #[test]
    fn block_toggle_and_remove_from_rules_tab() {
        let (mut m, t0) = monitor();
        m.probe.flows = vec![(key(50001), tx(10))];
        m.tick_at(secs(t0, 1));
        let mut app = App::default();
        m.handle(&mut app, Action::ToggleBlockRemote);
        assert_eq!(m.probe.table.len(), 1, "{}", app.status);
        assert_eq!((m.probe.table[0].fields, m.probe.table[0].prefix), (RULE_NET, 32));
        assert!(app.status.starts_with("blocked host 198.51.100.9"), "{}", app.status);
        m.handle(&mut app, Action::ToggleBlockPort);
        // New blocks go on top.
        let port = m.probe.table[0];
        assert_eq!((port.fields, port.port_lo, port.port_hi), (RULE_PROTO | RULE_PORT, 443, 443));
        m.tick_at(secs(t0, 2));
        // The fake reports 100 + slot hits and never resets. The host rule
        // had 100 hits before the rewrite and now sits in slot 1.
        assert_eq!((m.rules.rules[0].hits, m.rules.rules[1].hits), (100, 201), "hits read every tick");
        // b again unblocks; the port rule keeps its hits across the rewrite.
        m.handle(&mut app, Action::ToggleBlockRemote);
        assert_eq!(m.probe.table, vec![port]);
        assert_eq!(m.rules.rules[0].hits_base, 100);
        m.tick_at(secs(t0, 3));
        assert_eq!(m.rules.rules[0].hits, 200);
        // d in the Rules tab removes the selected rule.
        app.on_key(crate::app::Key::Char('5'));
        m.handle(&mut app, Action::RemoveRule);
        assert!(m.probe.table.is_empty() && m.rules.rules.is_empty(), "{}", app.status);
    }

    #[test]
    fn rules_file_owned_by_a_user_is_refused() {
        let (mut m, _) = monitor();
        let dir = std::env::temp_dir().join(format!("netmon-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.toml");
        std::fs::write(&path, "[[rule]]\naction = \"deny\"\nport = 25\n").unwrap();
        let a = Args { rules: Some(path.clone()), ..args(1000, 30) };
        let msg = m.load_rules_file(&a).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        // Tests run as a normal user, so the file is not root's.
        assert!(msg.contains("not owned by root") && msg.contains("no file rules loaded"), "{msg}");
        assert!(m.rules.rules.is_empty());
        let missing = Args { rules: Some(dir.join("gone.toml")), ..args(1000, 30) };
        assert!(m.load_rules_file(&missing).unwrap().contains("no file rules loaded"), "explicit path must exist");
    }

    #[test]
    fn kernel_verdicts_read_while_rules_are_in_force() {
        let (mut m, t0) = monitor();
        m.probe.flows = vec![(key(50001), tx(10))];
        let st = netmon_common::ConnState { dir: netmon_common::DIR_IN, action: netmon_common::ACTION_DENY, ..Default::default() };
        m.probe.conns.insert(netmon_common::ConnKey::from_flow(&key(50001)), st);
        m.tick_at(secs(t0, 1));
        assert_eq!(m.collector.flows[&key(50001)].conn, None, "no rules: not read");
        m.rules.default = rules::Action::Deny;
        m.tick_at(secs(t0, 2));
        assert_eq!(m.collector.flows[&key(50001)].conn, Some(st));
        let mut app = App::default();
        m.handle(&mut app, Action::ToggleBlockPort);
        assert_eq!(m.probe.default, netmon_common::ACTION_DENY, "default sent with the table");
    }

    #[test]
    fn dns_answers_name_flows() {
        let (mut m, t0) = monitor();
        m.probe.flows = vec![(key(50001), tx(10))];
        // Answer for example.com: A 198.51.100.9, the flows' remote address.
        let mut dns = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        dns.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        dns.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 9]);
        let mut ev = netmon_common::NameEvent {
            key: key(53),
            len: dns.len() as u16,
            kind: netmon_common::NAME_DNS,
            _pad: 0,
            data: [0; netmon_common::NAME_DATA],
        };
        ev.data[..dns.len()].copy_from_slice(&dns);
        m.probe.names.push_back(ev);
        m.tick_at(secs(t0, 1));
        assert_eq!(m.collector.flows[&key(50001)].host.as_deref(), Some("example.com"));
        assert_eq!(m.collector.flows[&key(50001)].host_source, "dns");
        let mut app = App::default();
        let rows = app.conn_rows(&m.collector, &m.names);
        assert_eq!(rows[0].remote, "example.com:443");
        assert_eq!(rows[0].remote_addr, "198.51.100.9:443");
        app.on_key(crate::app::Key::Char('h'));
        assert_eq!(app.conn_rows(&m.collector, &m.names)[0].remote, "198.51.100.9:443", "h shows addresses");

        // A ClientHello on this connection names it by SNI, over DNS.
        let mut hello = vec![0x16, 0x03, 0x01, 0, 0, 0x01, 0, 0, 0, 3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        let sni = b"cdn.example.net";
        let ext_len = (9 + sni.len()) as u16;
        hello.extend_from_slice(&ext_len.to_be_bytes());
        hello.extend_from_slice(&[0, 0]);
        hello.extend_from_slice(&((5 + sni.len()) as u16).to_be_bytes());
        hello.extend_from_slice(&((3 + sni.len()) as u16).to_be_bytes());
        hello.push(0);
        hello.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        hello.extend_from_slice(sni);
        let mut ev = netmon_common::NameEvent {
            key: key(50001),
            len: hello.len() as u16,
            kind: netmon_common::NAME_TLS,
            _pad: 0,
            data: [0; netmon_common::NAME_DATA],
        };
        ev.data[..hello.len()].copy_from_slice(&hello);
        m.probe.names.push_back(ev);
        m.tick_at(secs(t0, 2));
        let f = &m.collector.flows[&key(50001)];
        assert_eq!((f.host.as_deref(), f.host_source), (Some("cdn.example.net"), "tls"));
        // The connection expires: its name goes with it.
        m.probe.flows.clear();
        for s in 3..40 {
            m.tick_at(secs(t0, s));
        }
        assert!(m.sni.is_empty());
    }

    #[test]
    fn ask_answers_once_or_by_rule() {
        use crate::app::Answer;
        let (mut m, t0) = monitor();
        let me = std::process::id();
        let conn = |port, rport| netmon_common::ConnKey {
            local_port: port,
            remote_port: rport,
            ..netmon_common::ConnKey::from_flow(&key(443))
        };
        let ask = |k| netmon_common::AskEvent { key: k, tgid: me, _pad: 0 };
        let (k1, k2, k3) = (conn(40000, 443), conn(40001, 443), conn(40002, 80));
        for k in [k1, k2, k3] {
            m.probe.asks.push_back(ask(k));
        }
        m.poll_asks(t0);
        assert_eq!(m.asks.pending.len(), 1, "one question per program");
        assert_eq!(m.asks.pending[0].dests.len(), 2);
        assert!(!m.asks.pending[0].exe.is_empty(), "exe of this test process");
        let mut app = App::default();

        // o: only the selected destination (port 443, two connections), once.
        m.handle(&mut app, Action::Answer(Answer::Once { allow: true }));
        assert_eq!(m.probe.verdicts, vec![(k1, netmon_common::ACTION_ALLOW), (k2, netmon_common::ACTION_ALLOW)]);
        assert_eq!(m.asks.pending[0].dests.len(), 1, "port 80 still waits");

        // d with port scope: a temporary deny rule; the question is decided.
        m.handle(&mut app, Action::AskScope(1));
        m.handle(&mut app, Action::Answer(Answer::Rule { allow: false, always: false }));
        assert!(m.asks.pending.is_empty(), "{}", app.status);
        let r = &m.rules.rules[0];
        assert_eq!((r.action, r.temporary, r.m.ports), (rules::Action::Deny, true, Some((80, 80))));
        assert_eq!(m.probe.table.len(), 1, "rule in the kernel");
        assert!(!rulefile::render(&m.rules).contains("[[rule]]"), "temporary rules are not saved");

        // A with program scope: always; later connections of it are decided.
        m.probe.asks.push_back(ask(conn(40003, 8443)));
        m.poll_asks(t0);
        m.handle(&mut app, Action::Answer(Answer::Rule { allow: true, always: true }));
        assert!(m.asks.pending.is_empty());
        // Events queued before the answer do not bring the question back.
        m.probe.asks.push_back(ask(conn(40005, 8443)));
        m.probe.asks.push_back(ask(conn(40006, 9000)));
        m.poll_asks(t0);
        assert!(m.asks.pending.is_empty(), "the program rule decides them");
        assert!(rulefile::render(&m.rules).contains("action = \"allow\""));

        // A question nobody answers is denied after the timeout.
        // Unknown process: no program rule, but port and destination work.
        let unknown = netmon_common::AskEvent { key: conn(40004, 22), tgid: 0, _pad: 0 };
        m.probe.asks.push_back(unknown);
        m.poll_asks(t0);
        assert_eq!(m.asks.pending[0].comm, "unknown process");
        m.handle(&mut app, Action::AskScope(-1));
        m.handle(&mut app, Action::Answer(Answer::Rule { allow: true, always: false }));
        assert!(app.status.contains("process unknown"), "{}", app.status);
        m.handle(&mut app, Action::AskScope(1));
        m.handle(&mut app, Action::Answer(Answer::Rule { allow: true, always: false }));
        assert!(m.asks.pending.is_empty(), "{}", app.status);
        assert_eq!(m.rules.rules[0].m.to_string(), "tcp port 22");
        let unknown = netmon_common::AskEvent { key: conn(40007, 23), tgid: 0, _pad: 0 };
        m.probe.asks.push_back(unknown);
        m.poll_asks(t0);
        m.poll_asks(t0 + ask::ASK_TIMEOUT);
        assert_eq!(m.probe.verdicts.last(), Some(&(unknown.key, netmon_common::ACTION_DENY)));
        assert!(m.asks.pending.is_empty());
    }

    #[test]
    fn failed_block_leaves_no_rule() {
        let (mut m, t0) = monitor();
        m.probe.flows = vec![(key(50001), tx(10))];
        m.tick_at(secs(t0, 1));
        m.probe.fail_block = true;
        let mut app = App::default();
        m.handle(&mut app, Action::ToggleBlockRemote);
        assert!(app.status.contains("rule update failed"), "{}", app.status);
        assert!(m.rules.rules.is_empty());
    }

    #[test]
    fn process_block_marks_running_pids_by_exe() {
        let (mut m, t0) = monitor();
        m.probe.flows = vec![(key(50001), tx(10))];
        m.tick_at(secs(t0, 1));
        // This test process is a running process with a known exe.
        let me = std::env::current_exe().unwrap().to_string_lossy().into_owned();
        let pid = std::process::id();
        let f = m.collector.flows.get_mut(&key(50001)).unwrap();
        f.owner = Some(crate::procmap::Owner {
            details: Some(crate::procmap::ProcDetails { exe: me.clone(), ..Default::default() }),
            ..Owner::new(pid, "test")
        });
        let mut app = App { tab: Tab::Processes, ..App::default() };
        m.handle(&mut app, Action::ToggleBlockProcess);
        assert_eq!((m.probe.table[0].fields, m.probe.table[0].exe), (RULE_EXE, 1), "{}", app.status);
        assert_eq!(m.probe.exe_ids.get(&me), Some(&1));
        assert!(m.probe.marked.contains(&(1, pid)), "running pid marked at once");
    }
}

