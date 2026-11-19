//! Terminal UI loop and the `--once` table.

use std::time::{Duration, Instant};

use anyhow::Context as _;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::{
    app::{App, Key, human},
    client::Client,
    monitor::{Args, CAPTURE_POLL, DRAIN_BATCH, LINK_POLL, Monitor},
    rules, ui,
};

/// Entry point of the `netmon` binary.
pub fn run() -> anyhow::Result<()> {
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
        let mut client = Client::new(mon.snapshot(), &mut app);
        let mut next = Instant::now() + interval;
        while !app.quit {
            terminal.draw(|f| {
                let s = &client.snap;
                ui::draw(f, &mut app, &s.collector, &s.names, client.capture.as_ref(), &s.rules)
            })?;
            let mut timeout = next.saturating_duration_since(Instant::now());
            if mon.capture.as_ref().is_some_and(|c| c.info.running) {
                timeout = timeout.min(CAPTURE_POLL);
            }
            if mon.links.is_some() || mon.rules.default == rules::Action::Ask {
                timeout = timeout.min(LINK_POLL);
            }
            let was_paused = app.paused;
            let mut changed = false;
            if event::poll(timeout).context("poll terminal events")?
                && let Event::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
                && let Some(key) = map_key(k)
                && let Some(action) = app.on_key(key)
                && let Some(req) = client.action(&mut app, action)
            {
                let msg = mon.request(req.clone());
                client.add_packets(mon.take_packets());
                client.apply(mon.snapshot(), &mut app);
                client.replied(&mut app, &req, msg);
            }
            // Resume shows live data at once.
            changed |= was_paused && !app.paused;
            mon.drain_capture(DRAIN_BATCH);
            client.add_packets(mon.take_packets());
            changed |= mon.poll_asks(Instant::now());
            if let Some(e) = mon.check_links().first() {
                app.status = e.clone();
            }
            if Instant::now() >= next {
                next += interval;
                let errs = mon.tick();
                if let Some(e) = errs.first() {
                    app.status = e.clone();
                }
                changed = true;
            }
            if changed {
                client.apply(mon.snapshot(), &mut app);
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
