//! Packet capture: start, stop, follow a process, drain the ring.

use super::*;

impl<K: Kernel> Monitor<K> {
    /// A process capture follows the process: new flows join, closed ones leave.
    pub(crate) fn sync_process_capture(&mut self) -> anyhow::Result<()> {
        let Some(Capturing { info: CaptureInfo { target: Target::Process { pid, .. }, running: true, .. }, .. }) =
            &self.capture
        else {
            return Ok(());
        };
        let keys = self.process_flows(*pid);
        self.probe.capture_flows(&keys)
    }

    pub(crate) fn process_flows(&self, pid: u32) -> HashSet<netmon_common::FlowKey> {
        self.collector
            .flows
            .values()
            .filter(|f| f.owner.as_ref().is_some_and(|o| o.pid == pid))
            .map(|f| f.key)
            .collect()
    }

    /// Starts a capture. The old one ends first. If the new one fails,
    /// none runs: a process capture must not come back at the next tick.
    pub(crate) fn start_capture(&mut self, target: Target) -> anyhow::Result<()> {
        if let Some(cap) = self.capture.as_mut() {
            cap.info.running = false;
        }
        self.probe.capture_off()?;
        // Packets still queued belong to the old capture.
        self.probe.discard_packets();
        self.packets.clear();
        let started = match &target {
            Target::Interface { index, .. } => self.probe.capture_iface(*index),
            Target::Process { pid, .. } => self.probe.capture_flows(&self.process_flows(*pid)),
            Target::Connection { key, .. } => self.probe.capture_flows(&HashSet::from([*key])),
        };
        if let Err(e) = started {
            let _ = self.probe.capture_off();
            return Err(e);
        }
        self.capture = Some(Capturing {
            info: CaptureInfo { id: self.capture.as_ref().map_or(1, |c| c.info.id + 1), target, running: true, dropped: 0 },
            mono_to_wall: capture::mono_to_wall_offset(),
            drop_base: self.probe.capture_drops(),
        });
        Ok(())
    }

    /// Stops the capture. Packets already captured still go to the UI.
    pub(crate) fn stop_capture(&mut self) -> String {
        if !self.capture.as_ref().is_some_and(|c| c.info.running) {
            return "no capture running".into();
        }
        let mut msg = String::new();
        if let Err(e) = self.probe.capture_off() {
            msg = format!("stop failed: {e:#}");
        }
        // Keep what the kernel already captured. The ring holds at most
        // CAPTURE_RING_BYTES, so this ends.
        self.drain_capture(usize::MAX);
        if let Some(cap) = self.capture.as_mut() {
            cap.info.running = false;
        }
        msg
    }

    /// Moves up to `max` packets from the ring to the UI queue and updates
    /// the drop count.
    pub(crate) fn drain_capture(&mut self, max: usize) {
        let Some(cap) = self.capture.as_mut().filter(|c| c.info.running) else { return };
        let offset = cap.mono_to_wall;
        let queue = &mut self.packets;
        self.probe.drain_packets(max, |ev| queue.push(capture::raw_packet(ev, offset)));
        // No UI took them: keep the newest.
        if queue.len() > MAX_QUEUED_PACKETS {
            queue.drain(..queue.len() - MAX_QUEUED_PACKETS);
        }
        cap.info.dropped = self.probe.capture_drops().saturating_sub(cap.drop_base);
    }

    /// Takes the packets captured since the last call.
    pub(crate) fn take_packets(&mut self) -> Vec<RawPacket> {
        std::mem::take(&mut self.packets)
    }
}
