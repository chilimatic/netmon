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

pub use daemon::run as run_daemon;
pub use monitor::RulesFileError;
pub use notify::run as run_notify;
pub use tui::run;
