//! Captured packets in memory and .pcap export.

use std::{
    collections::VecDeque,
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use netmon_common::{FlowKey, PacketEvent};

use crate::decode::{Decoded, decode};

/// Packets kept in memory. Older ones are dropped first.
pub const MAX_PACKETS: usize = 20_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Interface { index: u32, name: String },
    Process { pid: u32, comm: String },
    Connection { key: FlowKey, label: String },
}

impl Target {
    pub fn label(&self) -> String {
        match self {
            Target::Interface { name, .. } => format!("interface {name}"),
            Target::Process { pid, comm } => format!("process {comm} ({pid})"),
            Target::Connection { label, .. } => format!("connection {label}"),
        }
    }
}

pub struct Captured {
    pub time: SystemTime,
    pub ifindex: u32,
    pub egress: bool,
    /// Original length on the wire, including the Ethernet header.
    pub orig_len: u32,
    /// Ethernet-framed bytes, at most CAPTURE_LEN (+14 if a header was added).
    pub data: Vec<u8>,
    pub decoded: Decoded,
}

impl Captured {
    /// Builds a packet from a ring buffer event. Devices without a link
    /// layer get a dummy Ethernet header (zero MACs) so every packet in a
    /// capture, and in the .pcap file, has the same framing.
    pub fn from_event(ev: &PacketEvent, mono_to_wall: i128) -> Self {
        let cap = (ev.cap_len as usize).min(ev.data.len());
        let mut data = Vec::with_capacity(cap + 14);
        let mut orig_len = ev.len;
        if ev.has_l2 == 0 {
            data.extend_from_slice(&[0; 12]);
            data.extend_from_slice(&ev.ethertype.to_be_bytes());
            orig_len += 14;
        }
        data.extend_from_slice(&ev.data[..cap]);
        let wall_ns = (ev.ts_ns as i128 + mono_to_wall).max(0) as u64;
        let decoded = decode(&data);
        Captured {
            time: UNIX_EPOCH + Duration::from_nanos(wall_ns),
            ifindex: ev.ifindex,
            egress: ev.egress != 0,
            orig_len,
            data,
            decoded,
        }
    }
}

pub struct Capture {
    pub target: Target,
    /// False after the user stopped the capture; packets stay for viewing.
    pub running: bool,
    pub packets: VecDeque<Captured>,
    /// Packets received from the kernel since start, including ones
    /// dropped from memory.
    pub received: u64,
    pub started: SystemTime,
    /// Keep the selection on the newest packet.
    pub follow: bool,
    pub selected: usize,
    /// CLOCK_MONOTONIC -> wall clock offset in nanoseconds.
    pub mono_to_wall: i128,
}

impl Capture {
    pub fn new(target: Target) -> Self {
        Capture {
            target,
            running: true,
            packets: VecDeque::new(),
            received: 0,
            started: SystemTime::now(),
            follow: true,
            selected: 0,
            mono_to_wall: mono_to_wall_offset(),
        }
    }

    pub fn push(&mut self, p: Captured) {
        self.received += 1;
        if self.packets.len() == MAX_PACKETS {
            self.packets.pop_front();
            self.selected = self.selected.saturating_sub(1);
        }
        self.packets.push_back(p);
        if self.follow {
            self.selected = self.packets.len() - 1;
        }
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.selected = 0;
    }

    pub fn select(&mut self, delta: isize) {
        let max = self.packets.len().saturating_sub(1);
        self.selected = self.selected.saturating_add_signed(delta).min(max);
        self.follow = self.selected == max;
    }
}

/// Offset to add to bpf_ktime_get_ns() values to get Unix-epoch nanoseconds.
fn mono_to_wall_offset() -> i128 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid pointer to a timespec on the stack.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    let mono = ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128;
    let wall = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as i128;
    wall - mono
}

const LINKTYPE_ETHERNET: u32 = 1;

/// Writes packets as a classic pcap file (microsecond timestamps).
pub fn write_pcap<'a>(w: &mut impl Write, packets: impl IntoIterator<Item = &'a Captured>) -> std::io::Result<()> {
    w.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
    w.write_all(&2u16.to_le_bytes())?;
    w.write_all(&4u16.to_le_bytes())?;
    w.write_all(&0i32.to_le_bytes())?; // thiszone
    w.write_all(&0u32.to_le_bytes())?; // sigfigs
    w.write_all(&65_535u32.to_le_bytes())?; // snaplen
    w.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
    for p in packets {
        let t = p.time.duration_since(UNIX_EPOCH).unwrap_or_default();
        w.write_all(&(t.as_secs() as u32).to_le_bytes())?;
        w.write_all(&t.subsec_micros().to_le_bytes())?;
        w.write_all(&(p.data.len() as u32).to_le_bytes())?;
        w.write_all(&p.orig_len.max(p.data.len() as u32).to_le_bytes())?;
        w.write_all(&p.data)?;
    }
    Ok(())
}

/// Saves the capture to `dir/netmon-<unix time>.pcap`. Under sudo the file
/// is handed to the invoking user so it does not stay owned by root.
pub fn save(cap: &Capture, dir: &Path) -> std::io::Result<PathBuf> {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let path = dir.join(format!("netmon-{secs}.pcap"));
    let mut w = BufWriter::new(File::create(&path)?);
    write_pcap(&mut w, &cap.packets)?;
    w.flush()?;
    drop(w);
    let id = |var: &str| std::env::var(var).ok().and_then(|v| v.parse::<u32>().ok());
    if let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) {
        let _ = std::os::unix::fs::chown(&path, Some(uid), Some(gid));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::tests::tcp_syn;
    use netmon_common::CAPTURE_LEN;

    fn event(data: &[u8], has_l2: bool) -> PacketEvent {
        let mut ev = PacketEvent {
            ts_ns: 2_000_000_000,
            ifindex: 3,
            len: data.len() as u32,
            cap_len: data.len() as u32,
            ethertype: 0x0800,
            egress: 1,
            has_l2: has_l2 as u8,
            data: [0; CAPTURE_LEN],
        };
        ev.data[..data.len()].copy_from_slice(data);
        ev
    }

    #[test]
    fn adds_dummy_ethernet_for_l3_devices() {
        let syn = tcp_syn();
        let p = Captured::from_event(&event(&syn[14..], false), 0);
        assert_eq!(p.data.len(), syn.len());
        assert_eq!(&p.data[12..14], &[0x08, 0x00]);
        assert_eq!(p.orig_len, syn.len() as u32);
        assert_eq!(p.decoded.summary.dst, "1.1.1.1:443");
        assert_eq!(p.time, UNIX_EPOCH + Duration::from_secs(2));
    }

    #[test]
    fn pcap_layout() {
        let p = Captured::from_event(&event(&tcp_syn(), true), 1_000_000_000);
        let mut out = Vec::new();
        write_pcap(&mut out, [&p]).unwrap();
        assert_eq!(out.len(), 24 + 16 + 54);
        assert_eq!(&out[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(u32::from_le_bytes(out[20..24].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(out[24..28].try_into().unwrap()), 3); // ts sec
        assert_eq!(u32::from_le_bytes(out[32..36].try_into().unwrap()), 54); // incl_len
        assert_eq!(&out[40..], &tcp_syn()[..]);
    }

    #[test]
    fn memory_cap_and_follow() {
        let mut c = Capture::new(Target::Interface { index: 1, name: "lo".into() });
        for _ in 0..MAX_PACKETS + 5 {
            c.push(Captured::from_event(&event(&tcp_syn(), true), 0));
        }
        assert_eq!(c.packets.len(), MAX_PACKETS);
        assert_eq!(c.received, (MAX_PACKETS + 5) as u64);
        assert_eq!(c.selected, MAX_PACKETS - 1);
        c.select(-10);
        assert!(!c.follow);
        c.push(Captured::from_event(&event(&tcp_syn(), true), 0));
        assert_eq!(c.selected, MAX_PACKETS - 12, "selection stays on the same packet");
    }
}
