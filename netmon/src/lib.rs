//! netmon: eBPF network monitor and firewall. The `netmon` binary is a thin
//! wrapper around [`run`].

mod app;
mod ask;
mod capture;
mod client;
mod collector;
mod daemon;
mod decode;
mod engine;
mod ifaces;
mod linkwatch;
mod monitor;
mod names;
mod netns;
mod probe;
mod procmap;
mod proto;
mod remote;
mod rulefile;
mod rules;
mod text;
mod tui;
mod ui;

pub use daemon::run as run_daemon;
pub use tui::run;
