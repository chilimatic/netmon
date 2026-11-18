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
    probe::Probe,
    procmap::SocketTable,
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

struct Monitor {
    probe: Probe,
    collector: Collector,
    names: Names,
    last: Instant,
    ticks: u64,
    capture: Option<Capture>,
    /// Copy of the collector shown while paused. Counting goes on behind it,
    /// so rates are right again after resume.
    frozen: Option<Collector>,
}

impl Monitor {
    fn new(args: &Args) -> anyhow::Result<(Self, Vec<String>)> {
        let mut probe = Probe::load()?;
        let ifs = ifaces::list();
        let errors = probe.attach_new(&ifs);
        if probe.attached_count() == 0 {
            anyhow::bail!("could not attach to any interface: {}", errors.join("; "));
        }
        let mut names = Names::default();
        names.update(&ifs);
        let collector = Collector::new(args.expire_ticks());
        let mon = Monitor { probe, collector, names, last: Instant::now(), ticks: 0, capture: None, frozen: None };
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
        let mut errors = Vec::new();
        // Interface hot-plug check every 2 ticks.
        if self.ticks.is_multiple_of(2) {
            let ifs = ifaces::list();
            self.names.update(&ifs);
            errors = self.probe.attach_new(&ifs);
        }
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        let expired = self.collector.ingest(self.probe.snapshot(), dt);
        self.probe.forget(&expired);
        self.collector.resolve(&SocketTable::read());
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
        match &target {
            Target::Interface { index, .. } => self.probe.capture_iface(*index)?,
            Target::Process { pid, .. } => self.probe.capture_flows(&self.process_flows(*pid))?,
            Target::Connection { key, .. } => self.probe.capture_flows(&HashSet::from([*key]))?,
        }
        self.capture = Some(Capture::new(target));
        Ok(())
    }

    fn drain_capture(&mut self) {
        let Some(cap) = self.capture.as_mut() else { return };
        let offset = cap.mono_to_wall;
        self.probe.drain_packets(DRAIN_BATCH, |ev| cap.push(Captured::from_event(ev, offset)));
    }

    /// Turns the selected row of a tab into a capture target.
    fn target_for(&self, app: &App, tab: Tab) -> Result<Target, String> {
        let pick = |len: usize| if len == 0 { None } else { Some(app.selected.min(len - 1)) };
        // Rows as the user sees them, so a paused view picks the shown row.
        let c = self.view();
        match tab {
            Tab::Interfaces => {
                let rows = app.iface_rows(c, &self.names);
                let r = pick(rows.len()).map(|i| &rows[i]).ok_or("no interface selected")?;
                Ok(Target::Interface { index: r.index, name: r.name.clone() })
            }
            Tab::Processes => {
                let rows = app.proc_rows(c);
                let r = pick(rows.len()).map(|i| &rows[i]).ok_or("no process selected")?;
                let pid = r.pid_num.ok_or("owner unknown: capture its connections instead")?;
                Ok(Target::Process { pid, comm: r.process.clone() })
            }
            Tab::Connections => {
                let rows = app.conn_rows(c, &self.names);
                let r = pick(rows.len()).map(|i| &rows[i]).ok_or("no connection selected")?;
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
        eprintln!("warning: attach {e}");
    }
    match args.once {
        Some(secs) => print_once(&mut mon, secs),
        None => run_tui(&mut mon, &args),
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

fn run_tui(mon: &mut Monitor, args: &Args) -> anyhow::Result<()> {
    let interval = args.interval();
    let mut app = App { interval_secs: interval.as_secs_f64(), ..App::default() };
    let mut terminal = ratatui::init();
    let result = (|| -> anyhow::Result<()> {
        mon.tick();
        let mut next = Instant::now() + interval;
        while !app.quit {
            let drops = if mon.capture.is_some() { mon.probe.capture_drops() } else { 0 };
            terminal.draw(|f| ui::draw(f, &mut app, mon.view(), &mon.names, mon.capture.as_ref(), drops))?;
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
            mon.drain_capture();
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
}
