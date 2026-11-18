mod app;
mod capture;
mod collector;
mod decode;
mod ifaces;
mod probe;
mod procmap;
mod text;
mod ui;

use std::{
    collections::HashSet,
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
    probe::{Kernel, Probe},
    procmap::{Owner, OwnerCache, ProcCache, SocketTable, read_details},
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
}

impl Monitor {
    fn new(args: &Args) -> anyhow::Result<(Self, Vec<String>)> {
        let probe = Probe::load()?;
        let hook_errors = probe.hook_errors.clone();
        let (mon, mut errors) = Monitor::with_kernel(probe, args)?;
        errors.extend(hook_errors);
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
        let collector = Collector::new(args.expire_ticks());
        let mon = Monitor { probe, collector, names, last: Instant::now(), ticks: 0, capture: None, frozen: None, owners: OwnerCache::default(), procs: ProcCache::default() };
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
        let mut errors = Vec::new();
        // Interface hot-plug check every 2 ticks.
        if self.ticks.is_multiple_of(2) {
            let ifs = ifaces::list();
            self.names.update(&ifs);
            errors = self.probe.attach_new(&ifs);
        }
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        let expired = self.collector.ingest(self.probe.snapshot(), dt);
        self.probe.forget(&expired);
        let probe = &self.probe;
        let kernel = |cookie| probe.sock_owner(cookie).map(|o| Owner::from_kernel(&o));
        self.collector.resolve(&SocketTable::read(&mut self.owners), kernel);
        self.procs.prune(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists());
        for o in self.collector.flows.values_mut().filter_map(|f| f.owner.as_mut()) {
            self.procs.fill(o, read_details);
        }
        self.ticks += 1;
        if let Err(e) = self.sync_process_capture() {
            errors.push(format!("capture: {e:#}"));
        }
        errors
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
                let rows = app.proc_rows(c);
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
            Tab::Capture => Err("select a row in another tab".into()),
        }
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
            terminal.draw(|f| ui::draw(f, &mut app, mon.view(), &mon.names, mon.capture.as_ref()))?;
            let mut timeout = next.saturating_duration_since(Instant::now());
            if mon.capture.as_ref().is_some_and(|c| c.running) {
                timeout = timeout.min(CAPTURE_POLL);
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
        Args { interval_ms, expire_secs, once: None }
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

    use netmon_common::{CAPTURE_LEN, FlowStats, IPPROTO_TCP, PacketEvent};

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
        let fake = Fake { flows: Vec::new(), ring: VecDeque::new(), mode: Mode::Off, drops: 0 };
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
}
