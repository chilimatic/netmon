//! netmon: eBPF network monitor and firewall. The `netmon` binary is a thin
//! wrapper around [`run`].

mod app;
mod ask;
mod blocklist;
mod btf;
mod capture;
mod client;
mod collector;
mod connlog;
mod daemon;
mod decode;
mod engine;
mod geo;
mod graph;
mod ifaces;
mod linkwatch;
mod monitor;
mod names;
mod netns;
mod notify;
mod probe;
mod profile;
mod procmap;
mod proto;
mod remote;
mod rulefile;
mod rules;
mod text;
mod tui;
mod ui;
mod usage;

/// Tests that create directories hold this lock: the socket bind test sets
/// a narrow umask for a moment, and a directory made in that moment gets
/// no execute bit.
#[cfg(test)]
pub(crate) fn test_fs_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

pub use daemon::run as run_daemon;
pub use monitor::RulesFileError;
pub use notify::run as run_notify;
pub use tui::run;
