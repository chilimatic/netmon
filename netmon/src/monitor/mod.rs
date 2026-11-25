//! The main loop's state: kernel probe, flows, owners, rules, names and
//! questions. `netmon --local` and `netmond` run it through the Engine.
//! The tick and the owners are here; rules, questions, hostnames, capture
//! and container tables have their own modules.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use crate::{
    app::Answer,
    ask,
    capture::{self, Target},
    collector::{self, Collector},
    ifaces::{self, Names},
    linkwatch::LinkWatch,
    names, netns,
    probe::{Kernel, Probe},
    procmap::{self, Listeners, Owner, OwnerCache, ProcCache, SocketTable, read_details},
    proto::{CaptureInfo, DestId, RawPacket, Request, Snapshot},
    rulefile,
    rules::{self, BlockTarget, Rules, guard_endpoints},
    text,
};

mod asks;
mod capturing;
mod containers;
mod hosts;
mod alerts;
pub(crate) mod listen;
mod logging;
mod ruleset;
#[cfg(test)]
mod tests;

pub(crate) use containers::{ContainerResult, container_of, container_reader};
pub use ruleset::RulesFileError;
use ruleset::{GUARD_REFRESH, Guard, read_resolv};
pub(crate) use alerts::COUNTRIES_PATH;
pub(crate) use ruleset::{PROFILES_DIR, check_profile_name};

/// Options of the monitor itself: in `netmon` local mode and in `netmond`.
pub(crate) const DEFAULT_INTERVAL_MS: u64 = 1000;
pub(crate) const DEFAULT_EXPIRE_SECS: u64 = 30;

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Refresh interval in milliseconds.
    #[arg(long, default_value_t = DEFAULT_INTERVAL_MS)]
    pub(crate) interval_ms: u64,
    /// Drop flows idle for this many seconds.
    #[arg(long, default_value_t = DEFAULT_EXPIRE_SECS)]
    pub(crate) expire_secs: u64,
    /// Rules file. Must belong to root and not be writable by group or
    /// others. [default: /etc/netmon/rules.toml, skipped if missing]
    #[arg(long, value_name = "PATH")]
    pub(crate) rules: Option<std::path::PathBuf>,
    /// Ask about outbound connections no rule decides (default action
    /// "ask"); unmatched inbound connections are denied.
    #[arg(long)]
    pub(crate) ask: bool,
    /// Local TCP port that is never blocked, for SSH (repeat for more).
    /// netmond guards 22 unless given; 0 guards none.
    #[arg(long = "guard-port", value_name = "PORT")]
    pub(crate) guard_ports: Vec<u16>,
}

impl Args {
    /// Refresh interval, at least 100 ms.
    pub(crate) fn interval(&self) -> Duration {
        Duration::from_millis(self.interval_ms.max(100))
    }

    /// Idle ticks before a flow expires, from the clamped interval.
    pub(crate) fn expire_ticks(&self) -> u32 {
        let ms = self.interval().as_millis() as u64;
        (self.expire_secs.saturating_mul(1000) / ms).clamp(1, u32::MAX as u64) as u32
    }
}

/// How often captured packets are read while a capture runs.
pub(crate) const CAPTURE_POLL: Duration = Duration::from_millis(50);
/// Max packets taken from the ring buffer per poll, so the UI stays responsive.
pub(crate) const DRAIN_BATCH: usize = 4_096;
/// Multicast or broadcast address.
fn is_group(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(a) => a.is_multicast() || a.is_broadcast(),
        std::net::IpAddr::V6(a) => a.is_multicast(),
    }
}

/// Shortest time between two /proc/*/fd scans for host sockets.
pub(crate) const FD_SCAN_GAP: Duration = Duration::from_secs(2);
/// Ticks between full scans for exe marks while the exec tracepoints run.
pub(crate) const EXE_SCAN_EVERY: u64 = 10;
/// Shortest time between two container table reads for new unowned
/// flows. One read covers every namespace: ~400 ms on a host with many
/// containers.
pub(crate) const CONTAINER_REFRESH: Duration = Duration::from_secs(10);
/// How often the list of network namespaces is rescanned.
pub(crate) const NETNS_RESCAN: Duration = Duration::from_secs(10);
/// Shortest time between container reads for questions: the question
/// should name the container before the user answers.
pub(crate) const ASK_CONTAINER_REFRESH: Duration = Duration::from_secs(1);
/// Asked connections remembered as already looked up; then forgotten.
pub(crate) const MAX_ASKS_TRIED: usize = 4_096;
/// Name of a question whose connections belong to several containers.
pub(crate) const SEVERAL: &str = "several containers or processes";
/// Most ask events read per poll.
pub(crate) const ASK_BATCH: usize = 256;
/// ClientHello first segments waiting for their second one.
pub(crate) const MAX_HELLO_PARTS: usize = 256;
/// Most name events read per refresh; the rest wait in the ring.
pub(crate) const NAME_BATCH: usize = 4_096;
/// How often the TUI loop checks for interface events between ticks.
pub(crate) const LINK_POLL: Duration = Duration::from_millis(200);

/// The running or last capture, on the kernel side.
pub(crate) struct Capturing {
    pub(crate) info: CaptureInfo,
    /// CLOCK_MONOTONIC -> wall clock offset in nanoseconds.
    mono_to_wall: i128,
    /// Kernel drop counter (counts since load) when the capture started.
    drop_base: u64,
}

/// Packets kept for the UI at most; older ones are dropped first. Matches
/// what the UI keeps.
pub(crate) const MAX_QUEUED_PACKETS: usize = capture::MAX_PACKETS;

/// The main loop's state. Generic over the kernel side so tests can run it
/// with a fake.
pub(crate) struct Monitor<K: Kernel = Probe> {
    pub(crate) probe: K,
    pub(crate) collector: Collector,
    pub(crate) names: Names,
    pub(crate) last: Instant,
    pub(crate) ticks: u64,
    pub(crate) capture: Option<Capturing>,
    /// Packets read from the kernel that no UI has taken yet.
    pub(crate) packets: Vec<RawPacket>,
    pub(crate) owners: OwnerCache,
    pub(crate) procs: ProcCache,
    pub(crate) rules: Rules,
    /// Interface events. None: fall back to a rescan every 2 ticks.
    pub(crate) links: Option<LinkWatch>,
    /// Where `s` in the Rules tab saves.
    pub(crate) rules_path: std::path::PathBuf,
    /// The rules file netmond started with (`--rules` or the default): the
    /// "default" profile. Profiles live next to it.
    pub(crate) base_rules_path: std::path::PathBuf,
    /// Hostnames from DNS answers.
    pub(crate) hosts: names::HostNames,
    /// Ask mode: questions waiting for the user.
    pub(crate) asks: ask::Asks,
    /// Their socket tables, read when needed (see refresh_containers).
    pub(crate) containers: Vec<procmap::ContainerTable>,
    pub(crate) containers_asked: Option<Instant>,
    pub(crate) containers_tx: std::sync::mpsc::SyncSender<()>,
    pub(crate) containers_rx: std::sync::mpsc::Receiver<ContainerResult>,
    /// Time per step, with NETMON_PROFILE set.
    pub(crate) prof: crate::profile::Profile,
    /// Finds new listeners that other hosts can reach.
    pub(crate) listen_watch: listen::ListenWatch,
    /// New listeners found by the last ticks, for the clients.
    pub(crate) new_listeners: Vec<listen::NewListener>,
    /// The connection log (daemon only).
    pub(crate) conn_log: Option<crate::connlog::ConnLog>,
    /// Traffic per program and day (daemon only).
    pub(crate) usage: Option<crate::usage::Usage>,
    /// Finds devices on the LANs; None in tests and with --no-devices.
    pub(crate) discovery: Option<crate::devices::Discovery>,
    pub(crate) devices: Vec<crate::devices::Device>,
    /// The DNS log: the newest answers, answers not sent to the UIs yet,
    /// and answers whose program is looked up at the next tick.
    pub(crate) dns_log: std::collections::VecDeque<crate::dnslog::DnsEntry>,
    pub(crate) new_dns: Vec<crate::dnslog::DnsEntry>,
    pub(crate) dns_pending: Vec<(netmon_common::FlowKey, crate::dnslog::DnsEntry)>,
    /// Rate and new-country alerts, and the ones not sent yet.
    pub(crate) alerts: alerts::Alerts,
    pub(crate) new_alerts: Vec<String>,
    /// Flows already logged, and flows seen once without an owner.
    pub(crate) log_done: HashSet<netmon_common::FlowKey>,
    pub(crate) log_pending: HashSet<netmon_common::FlowKey>,
    /// Unowned flows the container tables were already read for.
    pub(crate) containers_tried: HashSet<netmon_common::FlowKey>,
    /// Asked connections without a process the container tables were
    /// already read for.
    pub(crate) asks_tried: HashSet<netmon_common::ConnKey>,
    /// Ticks between full /proc scans for exe marks.
    pub(crate) exe_scan_every: u64,
    /// What the lockout guard holds. resolv.conf is read again every
    /// GUARD_REFRESH ticks: a network change brings new resolvers.
    pub(crate) guard: Guard,
    /// TLS server name per connection, from its ClientHello.
    pub(crate) sni: HashMap<netmon_common::FlowKey, String>,
    /// First segments of ClientHellos that continue in the next segment.
    pub(crate) hello_parts: HashMap<netmon_common::FlowKey, Vec<u8>>,
    /// Addresses of blocked hostnames: the name they were learned for and
    /// when. They expire like the names.
    pub(crate) blocked: HashMap<std::net::IpAddr, (String, Instant)>,
    /// Addresses as last written to HOST_BLOCKS.
    pub(crate) kernel_blocked: HashSet<std::net::IpAddr>,
    /// Names from answers of a trusted resolver (resolv.conf or a local
    /// stub): the only source of address blocks.
    pub(crate) trusted_hosts: names::HostNames,
    /// TCP DNS connections whose first segment was read: later segments
    /// are not the start of a message.
    pub(crate) tcp_dns_seen: HashSet<netmon_common::FlowKey>,
}

impl Monitor {
    /// With `pin_dir` (netmond) the kernel side stays in force after the
    /// process ends, until `Probe::unpin`.
    pub(crate) fn new(args: &Args, pin_dir: Option<&std::path::Path>) -> anyhow::Result<(Self, Vec<String>)> {
        let mut probe = Probe::load(pin_dir)?;
        let hook_errors = probe.hook_errors.clone();
        let exec_tracking = probe.exec_tracking;
        let guard = Guard { ssh: ssh_connection(), ports: args.guard_ports.clone(), resolv: read_resolv() };
        if let Err(e) = probe.set_guard(&guard.endpoints(), &guard.ports) {
            probe.unpin();
            return Err(e);
        }
        let (mut mon, mut errors) = match Monitor::with_kernel(probe, args) {
            Ok(m) => m,
            Err((mut probe, e)) => {
                probe.unpin();
                return Err(e);
            }
        };
        errors.extend(hook_errors);
        mon.guard = guard;
        mon.owners.min_gap = FD_SCAN_GAP;
        // The tracepoints mark new processes; the full scan only catches
        // what they missed.
        if exec_tracking {
            mon.exe_scan_every = EXE_SCAN_EVERY;
        }
        match mon.load_rules_file(args) {
            Ok(Some(msg)) => errors.push(msg),
            Ok(None) => {}
            // netmond does not start with fewer rules than the file has:
            // the pins of an earlier netmond stay in force.
            Err(e) if pin_dir.is_some() => {
                mon.probe.unpin();
                return Err(RulesFileError(e).into());
            }
            Err(e) => errors.push(e),
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
        // Sockets opened before the start have no owner in the new maps.
        let (conns, listeners) = crate::procmap::seed_entries(&crate::procmap::sockets_with_owners());
        let lost = mon.probe.seed(&conns, &listeners);
        if lost > 0 {
            errors.push(format!("{lost} existing sockets got no owner entry: maps full"));
        }
        // Only now, with rules, guard and owners in place, the programs of
        // an earlier netmond detach.
        if let Err(e) = mon.probe.commit_pins() {
            errors.push(format!("rules will not survive a crash: {e}"));
        }
        match LinkWatch::open() {
            Ok(w) => mon.links = Some(w),
            Err(e) => errors.push(format!("interface events off, polling instead: {e}")),
        }
        Ok((mon, errors))
    }
}

impl<K: Kernel> Monitor<K> {
    /// Gives the kernel side back on error, so the caller can clean up.
    pub(crate) fn with_kernel(mut probe: K, args: &Args) -> Result<(Self, Vec<String>), (K, anyhow::Error)> {
        let ifs = ifaces::list();
        let errors = probe.attach_new(&ifs);
        if probe.attached_count() == 0 {
            return Err((probe, anyhow::anyhow!("could not attach to any interface: {}", errors.join("; "))));
        }
        let mut names = Names::default();
        names.update(&ifs);
        let mut collector = Collector::new(args.expire_ticks());
        collector.counted = names.physical();
        let (containers_tx, containers_rx) = container_reader();
        let mon = Monitor { probe, collector, names, last: Instant::now(), ticks: 0, capture: None, packets: Vec::new(), owners: OwnerCache::default(), procs: ProcCache::default(), rules: Rules::default(), links: None, rules_path: rulefile::DEFAULT_PATH.into(), base_rules_path: rulefile::DEFAULT_PATH.into(), hosts: Default::default(), asks: Default::default(), containers: Vec::new(), containers_asked: None, containers_tx, containers_rx, sni: HashMap::new(), hello_parts: HashMap::new(), prof: crate::profile::Profile::from_env(), containers_tried: HashSet::new(), asks_tried: HashSet::new(), exe_scan_every: 1, guard: Guard::default(), blocked: HashMap::new(), kernel_blocked: HashSet::new(), trusted_hosts: Default::default(), tcp_dns_seen: HashSet::new(), listen_watch: Default::default(), new_listeners: Vec::new(), conn_log: None, usage: None, discovery: None, devices: Vec::new(), dns_log: Default::default(), new_dns: Vec::new(), dns_pending: Vec::new(), alerts: Default::default(), new_alerts: Vec::new(), log_done: HashSet::new(), log_pending: HashSet::new() };
        Ok((mon, errors))
    }

    /// Everything a UI shows.
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            collector: self.collector.clone(),
            names: self.names.clone(),
            rules: self.rules.clone(),
            questions: self.asks.pending.iter().cloned().collect(),
            capture: self.capture.as_ref().map(|c| c.info.clone()),
            devices: self.devices.clone(),
        }
    }

    /// Carries out a request of a UI. Returns a status message.
    pub(crate) fn request(&mut self, req: Request) -> String {
        match req {
            Request::ToggleBlock(target) => self.toggle_block(target),
            Request::RemoveRule(id) => self.remove_rule(id),
            Request::SetRuleTimer { id, secs } => self.set_rule_timer(id, secs),
            Request::BlockHost { pattern, comment } => self.block_host(&pattern, &comment),
            Request::RemoveHost(id) => self.remove_host(id),
            Request::ReloadBlocklists => self.reload_blocklists(),
            Request::LoadProfile(name) => self.load_profile(&name),
            Request::SaveRules => {
                let path = &self.rules_path;
                match rulefile::save(path, &rulefile::render(&self.rules)) {
                    Ok(()) => format!(
                        "saved {} rules and {} blocked hosts to {}",
                        self.rules.rules.iter().filter(|r| !r.temporary).count(),
                        self.rules.hosts.len(),
                        path.display()
                    ),
                    Err(e) => format!("save {} failed: {e}", path.display()),
                }
            }
            Request::Answer { question, dest, scope, answer } => self.answer(question, dest, scope, answer),
            Request::StartCapture(target) => match self.start_capture(target) {
                Ok(()) => String::new(),
                Err(e) => format!("capture failed: {e:#}"),
            },
            Request::StopCapture => self.stop_capture(),
            Request::AddAllowRules(list) => {
                let n = list.len();
                self.change_rules(|r| {
                    for (m, comment) in list {
                        r.insert(usize::MAX, rules::Action::Allow, m, &comment)?;
                    }
                    Ok(format!("{n} allow rules added at the end; s saves them"))
                })
            }
            Request::SetLimit { exe, up_mb, down_mb } => self.change_rules(|r| r.set_limit(&exe, up_mb, down_mb, "")),
            Request::WakeDevice(mac) => match &self.discovery {
                Some(d) => d.wake(mac),
                None => "device discovery is off (netmond --no-devices)".into(),
            },
            Request::CheckPorts(mac) => match &self.discovery {
                Some(d) => d.check_ports(mac),
                None => "device discovery is off (netmond --no-devices)".into(),
            },
            Request::ScanDevices => match &self.discovery {
                Some(d) => {
                    d.scan();
                    "device scan started: ARP requests to every address of the LANs".into()
                }
                None => "device discovery is off (netmond --no-devices)".into(),
            },
        }
    }

    /// Reads the counters, refreshes owners and attaches to new interfaces.
    pub(crate) fn tick(&mut self) -> Vec<String> {
        self.tick_at(Instant::now())
    }

    pub(crate) fn tick_at(&mut self, now: Instant) -> Vec<String> {
        let t_tick = Instant::now();
        let mut errors = match self.links {
            Some(_) => self.check_links(),
            // No interface events: hot-plug check every 2 ticks.
            None if self.ticks.is_multiple_of(2) => self.rescan_ifaces(),
            None => Vec::new(),
        };
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        let t = Instant::now();
        let expired = self.collector.ingest(self.probe.snapshot(), dt);
        self.probe.forget(&expired);
        self.prof.add("flow counters", t);
        let t = Instant::now();
        let bound: Vec<_> =
            self.probe.listeners().into_iter().map(|(proto, a, o)| (proto, a, Owner::from_kernel(&o))).collect();
        for (proto, addr, o) in self.listen_watch.check(&bound) {
            let exe = std::fs::read_link(format!("/proc/{}/exe", o.pid))
                .map(|p| crate::text::sanitize(&p.to_string_lossy()))
                .unwrap_or_default();
            // The kernel names the thread that bound; the process name is
            // in /proc.
            let comm = std::fs::read_to_string(format!("/proc/{}/comm", o.pid))
                .map(|c| crate::text::sanitize(c.trim_end()))
                .unwrap_or(o.comm);
            self.new_listeners.push(listen::NewListener { proto, addr, pid: o.pid, comm, exe });
        }
        let listeners = Listeners::build(bound);
        self.prof.add("listeners", t);
        let t = Instant::now();
        let probe = &self.probe;
        self.collector.resolve_kernel(|cookie| probe.sock_owner(cookie).map(|o| Owner::from_kernel(&o)));
        let unowned = self.collector.unowned();
        self.prof.add("kernel owners", t);
        let t = Instant::now();
        let scans = self.owners.scans;
        let table = SocketTable::read(&mut self.owners, |s| unowned.wants(s));
        self.prof.add("socket table", t);
        if self.owners.scans > scans {
            self.prof.add_time("fd scans in it (count)", Duration::ZERO);
        }
        // Container tables only for new TCP/UDP flows without an owner:
        // one read takes 150-250 ms. Flows that never get one (forwarded
        // traffic) ask once.
        let flows = &self.collector.flows;
        self.containers_tried.retain(|k| flows.contains_key(k));
        let new: Vec<_> = flows
            .values()
            .filter(|f| {
                f.owner_source < collector::OwnerSource::Container
                    && f.key.ifindex != netmon_common::LOOPBACK_IFINDEX
                    && matches!(f.key.proto, netmon_common::IPPROTO_TCP | netmon_common::IPPROTO_UDP)
                    // LAN multicast and broadcast (mDNS, SSDP, DHCP): a new
                    // flow per sender port, and no container socket.
                    && !is_group(f.local.ip())
                    && !self.containers_tried.contains(&f.key)
            })
            .map(|f| f.key)
            .collect();
        if !new.is_empty() && self.refresh_containers(now, CONTAINER_REFRESH) {
            self.containers_tried.extend(new);
        }
        self.take_containers();
        let t = Instant::now();
        let probe = &self.probe;
        let kernel = |cookie| probe.sock_owner(cookie).map(|o| Owner::from_kernel(&o));
        self.collector.resolve(&table, &self.containers, &listeners, kernel);
        self.prof.add("resolve owners", t);
        let t = Instant::now();
        self.procs.prune(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists());
        for o in self.collector.flows.values_mut().filter_map(|f| f.owner.as_mut()) {
            self.procs.fill(o, read_details);
        }
        self.prof.add("process details", t);
        if self.ticks.is_multiple_of(GUARD_REFRESH) {
            let resolv = read_resolv();
            if resolv != self.guard.resolv {
                let old = std::mem::replace(&mut self.guard.resolv, resolv);
                if let Err(e) = self.probe.set_guard(&self.guard.endpoints(), &self.guard.ports) {
                    self.guard.resolv = old;
                    errors.push(format!("guard update failed: {e:#}"));
                }
            }
        }
        if self.ticks.is_multiple_of(self.exe_scan_every) {
            let t = Instant::now();
            if let Some(e) = self.sync_exe_blocks() {
                errors.push(e);
            }
            self.prof.add("exe marks (/proc scan)", t);
        }
        let t = Instant::now();
        self.refresh_hits();
        self.refresh_conns();
        self.prof.add("rule hits + verdicts", t);
        let t = Instant::now();
        self.refresh_hosts(now);
        if let Some(e) = self.sync_host_blocks(now) {
            errors.push(e);
        }
        self.prof.add("hostnames", t);
        if let Some(m) = self.expire_rules(rules::unix_now()) {
            errors.push(m);
        }
        let t = Instant::now();
        if let Some(e) = self.log_connections(now) {
            errors.push(e);
        }
        self.prof.add("connection log", t);
        if self.rules.alerts.any() {
            let t = Instant::now();
            let cfg = self.rules.alerts;
            let found = self.alerts.check(&cfg, &self.collector.flows, &self.collector.counted, dt, now);
            self.new_alerts.extend(found);
            if let Some(e) = self.alerts.save(now, false) {
                errors.push(e);
            }
            self.prof.add("alerts", t);
        }
        if let Some(d) = self.discovery.as_mut() {
            let found = d.take(rules::unix_now());
            if let Some(list) = found.list {
                self.devices = list;
            }
            if self.rules.alerts.new_device {
                for n in found.new {
                    let maker = if n.vendor.is_empty() { String::new() } else { format!(" ({})", n.vendor) };
                    let ip = if n.ip.is_unspecified() { "IPv6 only".to_string() } else { n.ip.to_string() };
                    self.new_alerts.push(format!("new device on {}: {ip} {}{maker}", n.iface, crate::devices::mac_text(&n.mac)));
                }
            }
            if self.rules.alerts.device_changes {
                self.new_alerts.extend(found.changes);
            }
            errors.extend(found.messages);
            errors.extend(found.error);
            errors.extend(d.save(now, false));
        }
        if let Some(u) = self.usage.as_mut() {
            let t = Instant::now();
            u.count(&self.collector.flows, &self.collector.counted, &crate::usage::today());
            if let Some(e) = u.save(now, false) {
                errors.push(e);
            }
            self.prof.add("usage per program", t);
        }
        self.ticks += 1;
        if let Err(e) = self.sync_process_capture() {
            errors.push(format!("capture: {e:#}"));
        }
        self.prof.add("tick (all)", t_tick);
        errors
    }

    /// Attaches to interfaces that appeared since the last check.
    pub(crate) fn check_links(&mut self) -> Vec<String> {
        if self.links.as_ref().is_some_and(|l| l.changed()) { self.rescan_ifaces() } else { Vec::new() }
    }

    pub(crate) fn rescan_ifaces(&mut self) -> Vec<String> {
        let ifs = ifaces::list();
        self.names.update(&ifs);
        self.collector.counted = self.names.physical();
        self.probe.attach_new(&ifs)
    }

}

/// SSH_CONNECTION of the session netmon runs in. sudo usually drops it from
/// the environment, so the parent processes (the shell, sshd's child) are
/// asked too.
pub(crate) fn ssh_connection() -> Option<String> {
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
