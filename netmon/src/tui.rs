//! Terminal UI loop and the `--once` table. The UI runs the monitor in
//! this process (local mode, root) or talks to `netmond`.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context as _, bail};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::{
    app::{App, Key, Tab, human},
    client::Client,
    engine::Engine,
    monitor::{self, Monitor},
    proto::{self, Request, Snapshot, ToClient},
    remote::Remote,
    ui,
};

/// Live view of network connections: owning process, interface and
/// traffic. Talks to netmond if it runs, else monitors in this process
/// (needs root).
#[derive(Parser)]
#[command(version)]
struct TuiArgs {
    #[command(flatten)]
    monitor: monitor::Args,
    /// Sample for N seconds, print the connections once and exit (no TUI).
    #[arg(long, value_name = "SECONDS")]
    once: Option<u64>,
    /// Socket of netmond. Used if it exists, unless --local.
    #[arg(long, value_name = "PATH", default_value = proto::DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Monitor in this process (needs root), even if netmond runs.
    #[arg(long)]
    local: bool,
}

/// How often the UI reads netmond's messages.
const REMOTE_POLL: Duration = Duration::from_millis(50);

/// Where the UI's data comes from.
enum Backend {
    Local { engine: Box<Engine>, out: Vec<ToClient> },
    Remote(Remote),
}

impl Backend {
    fn send(&mut self, req: Request) -> anyhow::Result<()> {
        match self {
            Backend::Local { engine, out } => {
                out.extend(engine.request(req));
                Ok(())
            }
            Backend::Remote(r) => r.send(req),
        }
    }

    /// Messages ready now. Local mode does the monitor's due work here.
    fn poll(&mut self) -> anyhow::Result<Vec<ToClient>> {
        match self {
            Backend::Local { engine, out } => {
                let mut msgs = std::mem::take(out);
                msgs.extend(engine.step(Instant::now()));
                Ok(msgs)
            }
            Backend::Remote(r) => r.poll(),
        }
    }

    /// Longest wait for a key before the next poll.
    fn wait(&self) -> Duration {
        match self {
            Backend::Local { engine, out } if out.is_empty() => engine.wait(),
            Backend::Local { .. } => Duration::ZERO,
            Backend::Remote(_) => REMOTE_POLL,
        }
    }
}

/// Entry point of the `netmon` binary.
pub fn run() -> anyhow::Result<()> {
    let args = TuiArgs::parse();
    let remote = !args.local && std::fs::symlink_metadata(&args.socket).is_ok();
    // SAFETY: geteuid has no preconditions.
    if !remote && !args.local && unsafe { libc::geteuid() } != 0 {
        bail!(
            "netmond does not run ({} missing): start it with `sudo systemctl start netmond`, \
             or run netmon as root to monitor in this process",
            args.socket.display()
        );
    }
    if !remote {
        let (mut mon, errors) = Monitor::new(&args.monitor, None)?;
        for e in &errors {
            eprintln!("warning: {e}");
        }
        if let Some(secs) = args.once {
            return print_once(&mut mon, secs);
        }
        let engine = Box::new(Engine::new(mon, args.monitor.interval()));
        let snapshot = engine.mon.snapshot();
        let interval = engine.interval();
        return run_tui(Backend::Local { engine, out: Vec::new() }, snapshot, interval, errors.join("; "));
    }
    let m = &args.monitor;
    if m.rules.is_some() || m.ask {
        bail!("--rules and --ask set up netmond: give them to netmond, or use --local");
    }
    if m.interval_ms != monitor::DEFAULT_INTERVAL_MS || m.expire_secs != monitor::DEFAULT_EXPIRE_SECS {
        bail!("--interval-ms and --expire-secs set up netmond: give them to netmond, or use --local");
    }
    let (remote, welcome) = Remote::connect(&args.socket)?;
    if let Some(secs) = args.once {
        return print_remote_once(remote, welcome.snapshot, secs);
    }
    run_tui(Backend::Remote(remote), welcome.snapshot, welcome.interval, welcome.warnings.join("; "))
}

fn print_once(mon: &mut Monitor, secs: u64) -> anyhow::Result<()> {
    mon.tick();
    std::thread::sleep(Duration::from_secs(secs.max(1)));
    mon.tick();
    print_rows(&mon.snapshot());
    Ok(())
}

/// Waits `secs` and prints netmond's latest snapshot.
fn print_remote_once(mut remote: Remote, mut snap: Snapshot, secs: u64) -> anyhow::Result<()> {
    let end = Instant::now() + Duration::from_secs(secs.max(1));
    while Instant::now() < end {
        std::thread::sleep(REMOTE_POLL);
        for m in remote.poll()? {
            if let ToClient::Snapshot(s) = m {
                snap = *s;
            }
        }
    }
    print_rows(&snap);
    Ok(())
}

fn print_rows(snap: &Snapshot) {
    let rows = App::default().conn_rows(&snap.collector, &snap.names);
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
}

/// Time between two frames of the graph animation.
const ANIM_FRAME: Duration = Duration::from_millis(100);

fn run_tui(mut backend: Backend, snapshot: Snapshot, interval: Duration, status: String) -> anyhow::Result<()> {
    let mut app = App { interval_secs: interval.as_secs_f64(), status, ..App::default() };
    let mut client = Client::new(snapshot, &mut app);
    let mut terminal = ratatui::init();
    let mut frame = std::time::Instant::now();
    let result = (|| -> anyhow::Result<()> {
        while !app.quit {
            // The graph's dots move only while it shows and runs.
            let now = std::time::Instant::now();
            if app.tab == Tab::Graph && !app.paused {
                app.anim += now.duration_since(frame).as_secs_f64();
            }
            frame = now;
            terminal.draw(|f| {
                let s = &client.snap;
                ui::draw(f, &mut app, &s.collector, &s.names, client.capture.as_ref(), &s.rules)
            })?;
            let was_paused = app.paused;
            let mut wait = backend.wait();
            if app.tab == Tab::Graph && !app.paused {
                wait = wait.min(ANIM_FRAME);
            }
            if event::poll(wait).context("poll terminal events")?
                && let Event::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
                && let Some(key) = map_key(k)
                && let Some(action) = app.on_key(key)
                && let Some(req) = client.action(&mut app, action)
            {
                backend.send(req)?;
            }
            // Resume shows live data at once.
            if was_paused && !app.paused {
                client.resume();
            }
            for m in backend.poll()? {
                match m {
                    ToClient::Snapshot(s) => client.apply(*s, &mut app),
                    ToClient::Packets(p) => client.add_packets(p),
                    ToClient::Reply { req, msg } => client.replied(&mut app, &req, msg),
                    ToClient::Status(s) => app.status = s,
                    ToClient::Error(e) => bail!("netmond: {e}"),
                    ToClient::Hello { .. } => {}
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
