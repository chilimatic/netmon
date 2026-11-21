//! The Monitor on its clock: ticks, packet and question polling, and the
//! messages that go to the UIs. `netmon` (local mode) and `netmond` run the
//! same engine.

use std::time::{Duration, Instant};

use crate::{
    monitor::{CAPTURE_POLL, DRAIN_BATCH, LINK_POLL, Monitor},
    probe::{Kernel, Probe},
    proto::{Request, ToClient},
    rules,
};

pub(crate) struct Engine<K: Kernel = Probe> {
    pub(crate) mon: Monitor<K>,
    interval: Duration,
    next: Instant,
}

impl<K: Kernel> Engine<K> {
    /// Takes the first sample at once.
    pub(crate) fn new(mut mon: Monitor<K>, interval: Duration) -> Self {
        mon.tick();
        Engine { mon, interval, next: Instant::now() + interval }
    }

    pub(crate) fn interval(&self) -> Duration {
        self.interval
    }

    pub(crate) fn snapshot(&self) -> ToClient {
        ToClient::Snapshot(Box::new(self.mon.snapshot()))
    }

    /// How long the caller may wait before the next `step`.
    pub(crate) fn wait(&self) -> Duration {
        let mut t = self.next.saturating_duration_since(Instant::now());
        if self.mon.capture.as_ref().is_some_and(|c| c.info.running) {
            t = t.min(CAPTURE_POLL);
        }
        // Questions must show before the first TCP retransmit (~1 s).
        if self.mon.links.is_some() || self.mon.rules.default == rules::Action::Ask {
            t = t.min(LINK_POLL);
        }
        t
    }

    /// Carries out a request. The messages are, in order: new packets, a
    /// snapshot for every client, the reply for the asking client.
    pub(crate) fn request(&mut self, req: Request) -> Vec<ToClient> {
        let mut out = self.request_quiet(req);
        let reply = out.pop();
        out.push(self.snapshot());
        out.extend(reply);
        out
    }

    /// Like `request`, without the snapshot: netmond sends one snapshot
    /// for a batch of requests. In order: new packets, the reply.
    pub(crate) fn request_quiet(&mut self, req: Request) -> Vec<ToClient> {
        let msg = self.mon.request(req.clone());
        let mut out = self.packets();
        out.push(ToClient::Reply { req, msg });
        out
    }

    /// Does what is due: packets, questions, interface events, the tick.
    pub(crate) fn step(&mut self, now: Instant) -> Vec<ToClient> {
        let t = Instant::now();
        self.mon.drain_capture(DRAIN_BATCH);
        let mut out = self.packets();
        let mut changed = self.mon.poll_asks(now);
        let mut errors = self.mon.check_links();
        self.mon.prof.add("poll (packets, asks, links)", t);
        if now >= self.next {
            self.next += self.interval;
            // Far behind (suspend, stopped process): do not catch up.
            if self.next < now {
                self.next = now + self.interval;
            }
            errors.extend(self.mon.tick_at(now));
            changed = true;
        }
        if let Some(e) = errors.into_iter().next() {
            out.push(ToClient::Status(e));
        }
        if changed {
            let t = Instant::now();
            out.push(self.snapshot());
            self.mon.prof.add("snapshot copy", t);
        }
        self.mon.prof.report();
        out
    }

    fn packets(&mut self) -> Vec<ToClient> {
        let p = self.mon.take_packets();
        if p.is_empty() { Vec::new() } else { vec![ToClient::Packets(p)] }
    }
}
