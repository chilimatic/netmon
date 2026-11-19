//! Time spent per step of the monitor loop, for finding CPU hogs. On with
//! `NETMON_PROFILE=1`; then a summary goes to stderr every 30 s.

use std::time::{Duration, Instant};

const REPORT_EVERY: Duration = Duration::from_secs(30);

pub(crate) struct Profile {
    on: bool,
    /// Name, total time, calls; in first-seen order.
    phases: Vec<(&'static str, Duration, u32)>,
    since: Instant,
    cpu_since: Duration,
}

impl Profile {
    pub(crate) fn from_env() -> Self {
        let on = std::env::var_os("NETMON_PROFILE").is_some_and(|v| v != "0");
        Profile { on, phases: Vec::new(), since: Instant::now(), cpu_since: process_cpu() }
    }

    /// Adds the time since `start` to `name`.
    pub(crate) fn add(&mut self, name: &'static str, start: Instant) {
        self.add_time(name, start.elapsed());
    }

    pub(crate) fn add_time(&mut self, name: &'static str, d: Duration) {
        if !self.on {
            return;
        }
        match self.phases.iter_mut().find(|p| p.0 == name) {
            Some(p) => {
                p.1 += d;
                p.2 += 1;
            }
            None => self.phases.push((name, d, 1)),
        }
    }

    /// Prints and resets the totals every REPORT_EVERY.
    pub(crate) fn report(&mut self) {
        if !self.on || self.since.elapsed() < REPORT_EVERY {
            return;
        }
        let wall = self.since.elapsed();
        let cpu = process_cpu();
        let used = cpu.saturating_sub(self.cpu_since);
        eprintln!(
            "profile: {:.1} s CPU in {:.1} s ({:.0} % of one core, all threads)",
            used.as_secs_f64(),
            wall.as_secs_f64(),
            100.0 * used.as_secs_f64() / wall.as_secs_f64()
        );
        let mut phases = std::mem::take(&mut self.phases);
        phases.sort_by(|a, b| b.1.cmp(&a.1));
        for (name, total, calls) in phases {
            eprintln!(
                "profile:   {name:<22} {:>8.1} ms total {:>6} calls {:>8.2} ms/call {:>5.1} %",
                total.as_secs_f64() * 1e3,
                calls,
                total.as_secs_f64() * 1e3 / calls as f64,
                100.0 * total.as_secs_f64() / wall.as_secs_f64()
            );
        }
        self.since = Instant::now();
        self.cpu_since = cpu;
    }
}

/// User + system CPU time of the whole process.
fn process_cpu() -> Duration {
    // SAFETY: zeroed rusage is a valid buffer for getrusage.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return Duration::ZERO;
    }
    let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    tv(ru.ru_utime) + tv(ru.ru_stime)
}
