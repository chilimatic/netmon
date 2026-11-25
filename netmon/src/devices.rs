//! Devices on the local networks (Devices tab).
//!
//! The monitor finds them in three ways: an ARP request to every address of
//! each LAN (a sweep at start, on request and every 10 minutes), the ARP
//! traffic it hears, and the kernel neighbor table. The IEEE OUI list names
//! the maker. mDNS and reverse DNS give the name. netmond keeps the known
//! devices in /var/lib/netmon/devices.json. A device that is not in the file
//! raises an alert when `[alerts]` has `new_device = true`.
//!
//! The bytes of ARP and DNS replies come from the network and are untrusted:
//! every read is bounds-checked.

use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

pub const DEFAULT_PATH: &str = "/var/lib/netmon/devices.json";
/// Where distributions put the IEEE OUI list.
const OUI_FILES: [&str; 3] = ["/usr/share/hwdata/oui.txt", "/usr/share/ieee-data/oui.txt", "/usr/share/misc/oui.txt"];
const SWEEP_EVERY: Duration = Duration::from_secs(600);
const NEIGH_EVERY: Duration = Duration::from_secs(5);
const LAN_EVERY: Duration = Duration::from_secs(30);
/// Gap between two ARP requests of a sweep: a /24 takes about 0.5 s.
const SEND_GAP: Duration = Duration::from_millis(2);
/// Addresses swept per LAN at most. A larger LAN sweeps the /24 of the host.
const MAX_SWEEP: u32 = 1024;
const MAX_DEVICES: usize = 4096;
/// Without a devices file, the first minutes only learn: every device is new.
const LEARN: Duration = Duration::from_secs(120);
const SAVE_EVERY: Duration = Duration::from_secs(60);
/// A device seen in this time is online. Longer than the sweep interval.
pub const ONLINE_SECS: u64 = 15 * 60;
const MDNS_WAIT: Duration = Duration::from_millis(700);
const ETH_P_ARP: u16 = 0x0806;

/// One device on a LAN, by its MAC address.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Device {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub iface: String,
    /// The maker from the OUI list, or why there is none.
    pub vendor: String,
    /// From mDNS or reverse DNS; empty if neither answered.
    pub name: String,
    /// Unix seconds.
    pub first_seen: u64,
    pub last_seen: u64,
    /// The host netmon runs on.
    #[serde(default)]
    pub this_host: bool,
    /// A default gateway of the host.
    #[serde(default)]
    pub gateway: bool,
}

pub fn mac_text(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut m = [0u8; 6];
    let mut parts = s.split([':', '-']);
    for b in m.iter_mut() {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(m)
}

/// The IEEE OUI list: lines like `E8-1B-69   (hex)  Sagemcom Broadband SAS`
/// (tabs before the name).
pub fn parse_oui(text: &str) -> HashMap<[u8; 3], String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let Some((prefix, rest)) = line.split_once("(hex)") else { continue };
        let mut p = [0u8; 3];
        let mut parts = prefix.trim().split('-');
        let ok = p.iter_mut().all(|b| parts.next().and_then(|x| u8::from_str_radix(x, 16).ok()).map(|v| *b = v).is_some());
        let name = crate::text::sanitize(rest.trim());
        if ok && parts.next().is_none() && !name.is_empty() {
            out.insert(p, name);
        }
    }
    out
}

fn load_oui() -> HashMap<[u8; 3], String> {
    OUI_FILES.iter().find_map(|f| std::fs::read_to_string(f).ok()).map(|t| parse_oui(&t)).unwrap_or_default()
}

/// The maker of a MAC address. Phones and laptops often use a random
/// (locally administered) address on Wi-Fi: it has no maker.
pub fn vendor(oui: &HashMap<[u8; 3], String>, mac: &[u8; 6]) -> String {
    if mac[0] & 0x02 != 0 {
        return "(random MAC)".into();
    }
    oui.get(&[mac[0], mac[1], mac[2]]).cloned().unwrap_or_default()
}

/// Complete entries of /proc/net/arp: address, MAC, interface.
pub fn parse_neighbors(text: &str) -> Vec<(Ipv4Addr, [u8; 6], String)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (ip, flags, mac, dev) = (f.first()?, f.get(2)?, f.get(3)?, f.get(5)?);
            // ATF_COM: the entry has a MAC address.
            let flags = u32::from_str_radix(flags.trim_start_matches("0x"), 16).ok()?;
            let mac = parse_mac(mac)?;
            (flags & 0x2 != 0 && usable_mac(&mac)).then(|| Some((ip.parse().ok()?, mac, dev.to_string())))?
        })
        .collect()
}

/// Default gateways from /proc/net/route: interface and address.
pub fn gateways(text: &str) -> Vec<(String, Ipv4Addr)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (dev, dest, gw) = (f.first()?, f.get(1)?, f.get(2)?);
            // The file shows addresses as host-order hex: little-endian here.
            let gw = u32::from_str_radix(gw, 16).ok()?;
            (*dest == "00000000" && gw != 0).then(|| (dev.to_string(), Ipv4Addr::from(gw.swap_bytes())))
        })
        .collect()
}

fn usable_mac(m: &[u8; 6]) -> bool {
    *m != [0; 6] && *m != [0xff; 6] && m[0] & 0x01 == 0
}

/// An ARP request for `dst`, without the Ethernet header.
pub fn arp_request(src_mac: [u8; 6], src_ip: Ipv4Addr, dst: Ipv4Addr) -> [u8; 28] {
    let mut p = [0u8; 28];
    p[..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    p[8..14].copy_from_slice(&src_mac);
    p[14..18].copy_from_slice(&src_ip.octets());
    p[24..28].copy_from_slice(&dst.octets());
    p
}

/// The sender of an Ethernet/IPv4 ARP request or reply.
pub fn parse_arp(p: &[u8]) -> Option<([u8; 6], Ipv4Addr)> {
    if p.len() < 28 {
        return None;
    }
    let head = &p[..8];
    if head[..6] != [0, 1, 8, 0, 6, 4] || !matches!(head[7], 1 | 2) || head[6] != 0 {
        return None;
    }
    let mac: [u8; 6] = p.get(8..14)?.try_into().ok()?;
    let ip: [u8; 4] = p.get(14..18)?.try_into().ok()?;
    let ip = Ipv4Addr::from(ip);
    (usable_mac(&mac) && !ip.is_unspecified()).then_some((mac, ip))
}

pub fn in_subnet(a: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32)) };
    u32::from(a) & mask == u32::from(net) & mask
}

/// The addresses a sweep asks: all hosts of the LAN except the host's own,
/// or of its /24 if the LAN is larger than MAX_SWEEP.
pub fn sweep_targets(own: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    if prefix >= 31 {
        return Vec::new();
    }
    let prefix = if (1u64 << (32 - prefix)) > MAX_SWEEP as u64 { 24.max(prefix) } else { prefix };
    let mask = u32::MAX << (32 - prefix);
    let net = u32::from(own) & mask;
    let size = 1u32 << (32 - prefix);
    (1..size - 1).map(|i| Ipv4Addr::from(net + i)).filter(|a| *a != own).collect()
}

/// An mDNS/DNS query for the PTR record of `ip` (reverse lookup).
pub fn ptr_query(ip: Ipv4Addr, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(48);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let o = ip.octets();
    for label in [o[3].to_string(), o[2].to_string(), o[1].to_string(), o[0].to_string(), "in-addr".into(), "arpa".into()] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    // End of name, type PTR, class IN.
    q.extend_from_slice(&[0, 0, 12, 0, 1]);
    q
}

/// A LAN of the host: an Ethernet interface with an IPv4 subnet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lan {
    pub index: u32,
    pub name: String,
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

/// IPv4 subnets on physical Ethernet and Wi-Fi interfaces that use ARP.
/// Bridges and veths (containers) are left out.
fn lans() -> Vec<Lan> {
    let physical: HashMap<String, u32> = crate::ifaces::list()
        .into_iter()
        .filter(|i| i.kind == crate::ifaces::Kind::Physical)
        .map(|i| (i.name, i.index))
        .collect();
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a list that freeifaddrs releases below; the
    // loop only reads entries while the list lives.
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let a = &*cur;
            cur = a.ifa_next;
            if a.ifa_addr.is_null() || a.ifa_netmask.is_null() || (*a.ifa_addr).sa_family as i32 != libc::AF_INET {
                continue;
            }
            let flags = a.ifa_flags;
            if flags & libc::IFF_UP as u32 == 0 || flags & (libc::IFF_NOARP | libc::IFF_LOOPBACK) as u32 != 0 {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(a.ifa_name).to_string_lossy().into_owned();
            let Some(&index) = physical.get(&name) else { continue };
            let ip = Ipv4Addr::from(u32::from_be((*(a.ifa_addr as *const libc::sockaddr_in)).sin_addr.s_addr));
            let mask = u32::from_be((*(a.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr);
            let mac = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok().and_then(|m| parse_mac(m.trim()));
            let ty = std::fs::read_to_string(format!("/sys/class/net/{name}/type")).unwrap_or_default();
            if let Some(mac) = mac
                && ty.trim() == "1"
                && mask.count_ones() <= 30
            {
                out.push(Lan { index, name, mac, ip, prefix: mask.count_ones() as u8 });
            }
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// What the discovery threads found, shared with the monitor.
#[derive(Default)]
struct State {
    devices: HashMap<[u8; 6], Device>,
    /// MACs first seen since the last `take`.
    new: Vec<[u8; 6]>,
    changed: bool,
    dirty: bool,
    learn_until: Option<Instant>,
    error: Option<String>,
    /// Default gateways of the host: interface and address.
    gateways: Vec<(String, Ipv4Addr)>,
}

impl State {
    /// Records `mac` at `ip`. `heard`: the device itself sent this now (ARP),
    /// not an old neighbor table entry. Returns true when a name lookup is
    /// due (new device or new address).
    #[allow(clippy::too_many_arguments)]
    fn see(&mut self, oui: &HashMap<[u8; 3], String>, iface: &str, mac: [u8; 6], ip: Ipv4Addr, heard: bool, unix: u64, now: Instant) -> bool {
        if let Some(d) = self.devices.get_mut(&mac) {
            let moved = d.ip != ip || d.iface != iface;
            if moved {
                d.ip = ip;
                d.iface = iface.to_string();
                d.name.clear();
                d.gateway = self.gateways.iter().any(|(dev, gw)| dev == iface && *gw == ip);
            }
            if heard && d.last_seen != unix {
                d.last_seen = unix;
            } else if !moved {
                return false;
            }
            self.changed = true;
            self.dirty = true;
            return moved;
        }
        if self.devices.len() >= MAX_DEVICES {
            return false;
        }
        let d = Device {
            mac,
            ip,
            iface: iface.to_string(),
            vendor: vendor(oui, &mac),
            name: String::new(),
            first_seen: unix,
            last_seen: unix,
            this_host: false,
            gateway: self.gateways.iter().any(|(dev, gw)| dev == iface && *gw == ip),
        };
        self.devices.insert(mac, d);
        if self.learn_until.is_none_or(|t| now >= t) {
            self.new.push(mac);
        }
        self.changed = true;
        self.dirty = true;
        true
    }
}

/// The discovery threads and their results. Dropping it stops them.
pub(crate) struct Discovery {
    state: Arc<Mutex<State>>,
    scan: mpsc::Sender<()>,
    /// Where the known devices are kept (daemon only), and the file's group.
    path: Option<PathBuf>,
    gid: Option<u32>,
    saved: Option<Instant>,
}

impl Discovery {
    /// Loads the devices file and starts the threads. Returns a message if
    /// the file could not be read.
    pub(crate) fn start(path: Option<PathBuf>, gid: Option<u32>) -> (Self, Option<String>) {
        let mut st = State::default();
        let mut msg = None;
        match path.as_deref().map(std::fs::read_to_string) {
            Some(Ok(text)) => match serde_json::from_str::<Vec<Device>>(&text) {
                Ok(list) => st.devices = list.into_iter().take(MAX_DEVICES).map(|d| (d.mac, d)).collect(),
                Err(e) => {
                    msg = Some(format!("devices file {}: {e}; starting a new one", path.as_deref().map(|p| p.display().to_string()).unwrap_or_default()));
                    st.learn_until = Some(Instant::now() + LEARN);
                }
            },
            Some(Err(e)) if e.kind() != std::io::ErrorKind::NotFound => {
                msg = Some(format!("devices file: {e}"));
                st.learn_until = Some(Instant::now() + LEARN);
            }
            // No file yet, or local mode: learn first.
            _ => st.learn_until = Some(Instant::now() + LEARN),
        }
        st.changed = true;
        let state = Arc::new(Mutex::new(st));
        let (scan, scan_rx) = mpsc::channel();
        let (names_tx, names_rx) = mpsc::channel();
        // Tests never send ARP requests into the network they run on.
        if cfg!(test) {
            return (Discovery { state, scan, path, gid, saved: None }, msg);
        }
        let s = state.clone();
        std::thread::Builder::new()
            .name("netmon-arp".into())
            .spawn(move || arp_thread(s, scan_rx, names_tx))
            .ok();
        let s = state.clone();
        std::thread::Builder::new().name("netmon-names".into()).spawn(move || name_thread(s, names_rx)).ok();
        (Discovery { state, scan, path, gid, saved: None }, msg)
    }

    /// Asks for a sweep now.
    pub(crate) fn scan(&self) {
        let _ = self.scan.send(());
    }

    /// The device list if it changed, the new devices since the last call,
    /// and an error of the threads (once).
    pub(crate) fn take(&mut self) -> (Option<Vec<Device>>, Vec<Device>, Option<String>) {
        let Ok(mut st) = self.state.lock() else { return (None, Vec::new(), None) };
        let new: Vec<Device> = std::mem::take(&mut st.new).iter().filter_map(|m| st.devices.get(m).cloned()).collect();
        let list = std::mem::take(&mut st.changed).then(|| {
            let mut l: Vec<Device> = st.devices.values().cloned().collect();
            l.sort_by_key(|d| (d.iface.clone(), u32::from(d.ip)));
            l
        });
        (list, new, st.error.take())
    }

    /// Writes the devices file if it changed and a minute passed (or
    /// `force`). Returns an error message.
    pub(crate) fn save(&mut self, now: Instant, force: bool) -> Option<String> {
        let path = self.path.clone()?;
        if !force && self.saved.is_some_and(|s| now.duration_since(s) < SAVE_EVERY) {
            return None;
        }
        let text = {
            let mut st = self.state.lock().ok()?;
            if !std::mem::take(&mut st.dirty) {
                return None;
            }
            let mut l: Vec<&Device> = st.devices.values().filter(|d| !d.this_host).collect();
            l.sort_by_key(|d| d.mac);
            serde_json::to_string(&l).unwrap_or_default()
        };
        self.saved = Some(now);
        crate::usage::write_private(&path, text.as_bytes(), self.gid).err().map(|e| format!("devices file {}: {e}", path.display()))
    }
}

/// Sends ARP requests, listens to ARP and reads the neighbor table. Ends
/// when the Discovery is dropped.
fn arp_thread(state: Arc<Mutex<State>>, scan: mpsc::Receiver<()>, names: mpsc::Sender<([u8; 6], Ipv4Addr)>) {
    let report = |e: String| {
        if let Ok(mut st) = state.lock() {
            st.error = Some(e);
        }
    };
    // SAFETY: plain socket calls; the fd is closed when the loop ends.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, arp_protocol()) };
    if fd < 0 {
        report(format!("device discovery off: ARP socket: {}", std::io::Error::last_os_error()));
        return;
    }
    let tv = libc::timeval { tv_sec: 0, tv_usec: 300_000 };
    // SAFETY: tv outlives the call; the size matches.
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, size_of::<libc::timeval>() as u32);
    }
    let oui = load_oui();
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").map(|h| crate::text::sanitize(h.trim())).unwrap_or_default();
    let mut lan_list: Vec<Lan> = Vec::new();
    let (mut next_lan, mut next_sweep, mut next_neigh) = (Instant::now(), Instant::now(), Instant::now());
    let mut buf = [0u8; 256];
    let lookup = |mac, ip| {
        let _ = names.send((mac, ip));
    };
    loop {
        let now = Instant::now();
        let unix = crate::rules::unix_now();
        let mut manual = false;
        loop {
            match scan.try_recv() {
                Ok(()) => manual = true,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // SAFETY: fd is ours.
                    unsafe { libc::close(fd) };
                    return;
                }
            }
        }
        if now >= next_lan || manual {
            next_lan = now + LAN_EVERY;
            lan_list = lans();
            let gws = std::fs::read_to_string("/proc/net/route").map(|t| gateways(&t)).unwrap_or_default();
            if let Ok(mut st) = state.lock() {
                st.gateways = gws.clone();
                for l in &lan_list {
                    st.see(&oui, &l.name, l.mac, l.ip, true, unix, now);
                    // The host itself is no new device, and has its own name.
                    st.new.retain(|m| *m != l.mac);
                    if let Some(d) = st.devices.get_mut(&l.mac)
                        && (!d.this_host || d.name.is_empty())
                    {
                        d.this_host = true;
                        d.name = host.clone();
                        st.changed = true;
                    }
                }
                let mut changed = false;
                for d in st.devices.values_mut() {
                    let gw = gws.iter().any(|(dev, ip)| *dev == d.iface && *ip == d.ip);
                    if d.gateway != gw {
                        d.gateway = gw;
                        changed = true;
                    }
                }
                st.changed |= changed;
            }
        }
        if now >= next_sweep || manual {
            next_sweep = now + SWEEP_EVERY;
            if manual && let Ok(st) = state.lock() {
                for d in st.devices.values().filter(|d| d.name.is_empty() && !d.this_host) {
                    lookup(d.mac, d.ip);
                }
            }
            for l in &lan_list {
                if let Err(e) = sweep(fd, l) {
                    report(format!("ARP sweep on {}: {e}", l.name));
                }
            }
        }
        if now >= next_neigh {
            next_neigh = now + NEIGH_EVERY;
            let neigh = std::fs::read_to_string("/proc/net/arp").map(|t| parse_neighbors(&t)).unwrap_or_default();
            if let Ok(mut st) = state.lock() {
                for (ip, mac, dev) in neigh {
                    if let Some(l) = lan_list.iter().find(|l| l.name == dev && in_subnet(ip, l.ip, l.prefix))
                        && st.see(&oui, &l.name, mac, ip, false, unix, now)
                    {
                        lookup(mac, ip);
                    }
                }
            }
        }
        // SAFETY: buf and sll outlive the call; the sizes match.
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut len = size_of::<libc::sockaddr_ll>() as u32;
        let n = unsafe {
            libc::recvfrom(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0, &mut sll as *mut _ as *mut libc::sockaddr, &mut len)
        };
        if n <= 0 {
            continue;
        }
        let Some((mac, ip)) = parse_arp(&buf[..n as usize]) else { continue };
        let Some(l) = lan_list.iter().find(|l| l.index as i32 == sll.sll_ifindex) else { continue };
        if mac == l.mac || !in_subnet(ip, l.ip, l.prefix) {
            continue;
        }
        if let Ok(mut st) = state.lock()
            && st.see(&oui, &l.name, mac, ip, true, crate::rules::unix_now(), Instant::now())
        {
            lookup(mac, ip);
        }
    }
}

/// The protocol argument of an ARP packet socket: the 16-bit EtherType in
/// network byte order.
fn arp_protocol() -> i32 {
    ETH_P_ARP.to_be() as i32
}

/// One ARP request to each address of the LAN, broadcast.
fn sweep(fd: i32, l: &Lan) -> std::io::Result<()> {
    // SAFETY: zeroed sockaddr_ll is valid; the fields are set below.
    let mut to: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    to.sll_family = libc::AF_PACKET as u16;
    to.sll_protocol = ETH_P_ARP.to_be();
    to.sll_ifindex = l.index as i32;
    to.sll_halen = 6;
    to.sll_addr[..6].copy_from_slice(&[0xff; 6]);
    for dst in sweep_targets(l.ip, l.prefix) {
        let p = arp_request(l.mac, l.ip, dst);
        // SAFETY: p and to outlive the call; the sizes match.
        let n = unsafe {
            libc::sendto(fd, p.as_ptr() as *const libc::c_void, p.len(), 0, &to as *const _ as *const libc::sockaddr, size_of::<libc::sockaddr_ll>() as u32)
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        std::thread::sleep(SEND_GAP);
    }
    Ok(())
}

/// Looks up names for (MAC, address) pairs: mDNS first, then reverse DNS.
fn name_thread(state: Arc<Mutex<State>>, rx: mpsc::Receiver<([u8; 6], Ipv4Addr)>) {
    let mut asked: HashSet<([u8; 6], Ipv4Addr)> = HashSet::new();
    let mut since = Instant::now();
    while let Ok((mac, ip)) = rx.recv() {
        // A manual scan asks again for devices without a name.
        if since.elapsed() > Duration::from_secs(5) {
            asked.clear();
            since = Instant::now();
        }
        if !asked.insert((mac, ip)) {
            continue;
        }
        let Some(name) = mdns_name(ip).or_else(|| reverse_dns(ip)) else { continue };
        if let Ok(mut st) = state.lock()
            && let Some(d) = st.devices.get_mut(&mac)
            && d.ip == ip
            && !d.this_host
            && d.name != name
        {
            d.name = name;
            st.changed = true;
            st.dirty = true;
        }
    }
}

/// Asks the device itself on the mDNS port (a "legacy unicast" query: it
/// answers to our port). Apple devices, printers and Linux with Avahi answer.
fn mdns_name(ip: Ipv4Addr) -> Option<String> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.set_read_timeout(Some(MDNS_WAIT)).ok()?;
    let id = (crate::rules::unix_now() as u16) ^ u32::from(ip) as u16;
    s.send_to(&ptr_query(ip, id), SocketAddr::from((ip, 5353))).ok()?;
    let end = Instant::now() + MDNS_WAIT;
    let mut buf = [0u8; 1500];
    while Instant::now() < end {
        let (n, from) = s.recv_from(&mut buf).ok()?;
        if from.ip() == ip
            && let Some(name) = crate::names::ptr_answer(&buf[..n])
        {
            return Some(name);
        }
    }
    None
}

/// The system resolver's name for `ip` (the router often knows DHCP names).
fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    // SAFETY: sa and host outlive the call; the sizes match.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_addr.s_addr = u32::from(ip).to_be();
    let mut host = [0 as libc::c_char; 256];
    let r = unsafe {
        libc::getnameinfo(
            &sa as *const _ as *const libc::sockaddr,
            size_of::<libc::sockaddr_in>() as u32,
            host.as_mut_ptr(),
            host.len() as u32,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if r != 0 {
        return None;
    }
    // SAFETY: getnameinfo wrote a NUL-terminated string on success.
    let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }.to_string_lossy().trim_end_matches('.').to_ascii_lowercase();
    let ok = !name.is_empty() && name.len() <= 253 && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._".contains(&c));
    ok.then_some(name)
}

/// "now", "5m", "3h", "2d": how long ago `unix` was.
pub fn ago(unix: u64, now: u64) -> String {
    let s = now.saturating_sub(unix);
    match s {
        0..60 => "now".into(),
        60..3600 => format!("{}m", s / 60),
        3600..86_400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_oui_lines_and_names_makers() {
        let oui = parse_oui(
            "OUI/MA-L\t\t\tOrganization\n\nE8-1B-69   (hex)\t\tSagemcom Broadband SAS\nE81B69     (base 16)\t\tSagemcom Broadband SAS\n\
             zz-00-00   (hex)\t\tBroken\n",
        );
        assert_eq!(oui.len(), 1);
        assert_eq!(vendor(&oui, &[0xe8, 0x1b, 0x69, 1, 2, 3]), "Sagemcom Broadband SAS");
        assert_eq!(vendor(&oui, &[0x00, 0x1b, 0x69, 1, 2, 3]), "");
        assert_eq!(vendor(&oui, &[0xda, 0x1b, 0x69, 1, 2, 3]), "(random MAC)");
    }

    #[test]
    fn reads_neighbors_and_gateways() {
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
                   192.168.1.1      0x1         0x2         e8:1b:69:50:b4:28     *        enp5s0\n\
                   192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        enp5s0\n";
        assert_eq!(parse_neighbors(arp), vec![(Ipv4Addr::new(192, 168, 1, 1), [0xe8, 0x1b, 0x69, 0x50, 0xb4, 0x28], "enp5s0".into())]);
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     enp5s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                     enp5s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(gateways(route), vec![("enp5s0".into(), Ipv4Addr::new(192, 168, 1, 1))]);
    }

    #[test]
    fn arp_round_trip_and_rejects() {
        let mac = [2, 0, 0, 0, 0, 9];
        let p = arp_request(mac, Ipv4Addr::new(192, 168, 1, 140), Ipv4Addr::new(192, 168, 1, 7));
        assert_eq!(parse_arp(&p), Some((mac, Ipv4Addr::new(192, 168, 1, 140))));
        assert_eq!(parse_arp(&p[..20]), None, "cut off");
        let mut probe = p;
        probe[14..18].fill(0);
        assert_eq!(parse_arp(&probe), None, "ARP probe: sender 0.0.0.0");
        let mut other = p;
        other[2] = 0x86;
        assert_eq!(parse_arp(&other), None, "not IPv4");
    }

    #[test]
    fn sweeps_the_subnet_without_the_host() {
        let t = sweep_targets(Ipv4Addr::new(192, 168, 1, 140), 24);
        assert_eq!(t.len(), 253);
        assert_eq!(t[0], Ipv4Addr::new(192, 168, 1, 1));
        assert!(!t.contains(&Ipv4Addr::new(192, 168, 1, 140)) && !t.contains(&Ipv4Addr::new(192, 168, 1, 255)));
        assert_eq!(sweep_targets(Ipv4Addr::new(10, 1, 2, 3), 8).len(), 253, "large LAN: its /24 only");
        assert_eq!(sweep_targets(Ipv4Addr::new(10, 0, 4, 3), 22).len(), 1021);
        assert!(sweep_targets(Ipv4Addr::new(100, 96, 0, 2), 32).is_empty());
        assert!(in_subnet(Ipv4Addr::new(192, 168, 1, 9), Ipv4Addr::new(192, 168, 1, 140), 24));
        assert!(!in_subnet(Ipv4Addr::new(192, 168, 2, 9), Ipv4Addr::new(192, 168, 1, 140), 24));
    }

    #[test]
    fn ptr_query_and_answer() {
        let q = ptr_query(Ipv4Addr::new(192, 168, 1, 7), 0x1234);
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert!(q.ends_with(b"\x07in-addr\x04arpa\x00\x00\x0c\x00\x01"));
        // The answer: the query as response, plus one PTR record that points
        // back to the question name.
        let mut a = q.clone();
        a[2] = 0x84;
        a[7] = 1;
        a.extend_from_slice(&[0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 10]);
        let target = b"\x06iphone\x05local\x00";
        a.extend_from_slice(&(target.len() as u16).to_be_bytes());
        a.extend_from_slice(target);
        assert_eq!(crate::names::ptr_answer(&a).as_deref(), Some("iphone.local"));
        assert_eq!(crate::names::ptr_answer(&q), None, "a query is no answer");
        assert_eq!(crate::names::ptr_answer(&a[..a.len() - 3]), None, "cut off");
    }

    #[test]
    fn state_learns_first_then_reports_new_devices() {
        let oui = HashMap::new();
        let t0 = Instant::now();
        let mut st = State { learn_until: Some(t0 + LEARN), ..State::default() };
        st.gateways = vec![("eth0".into(), Ipv4Addr::new(10, 0, 0, 1))];
        st.see(&oui, "eth0", [0, 1, 2, 3, 4, 1], Ipv4Addr::new(10, 0, 0, 1), false, 100, t0);
        assert!(st.devices[&[0, 1, 2, 3, 4, 1]].gateway, "marked when first seen");
        assert_eq!((arp_protocol() as u16).to_ne_bytes(), [0x08, 0x06], "network byte order");
        let (a, b) = ([0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 6]);
        assert!(st.see(&oui, "eth0", a, Ipv4Addr::new(10, 0, 0, 2), true, 100, t0), "new: look up its name");
        assert!(st.new.is_empty(), "learning");
        st.devices.get_mut(&a).unwrap().name = "nas".into();
        assert!(!st.see(&oui, "eth0", a, Ipv4Addr::new(10, 0, 0, 2), false, 200, t0), "known");
        assert_eq!(st.devices[&a].last_seen, 100, "an old table entry is no sign of life");
        st.see(&oui, "eth0", a, Ipv4Addr::new(10, 0, 0, 2), true, 300, t0);
        assert_eq!(st.devices[&a].last_seen, 300);
        assert!(st.see(&oui, "eth0", a, Ipv4Addr::new(10, 0, 0, 3), true, 300, t0), "new address: look up again");
        assert!(st.devices[&a].name.is_empty());
        st.see(&oui, "eth0", b, Ipv4Addr::new(10, 0, 0, 4), true, 400, t0 + LEARN);
        assert_eq!(st.new, vec![b], "after learning");
        assert_eq!(ago(100, 100), "now");
        assert_eq!(ago(100, 100 + 3 * 3600), "3h");
    }

    #[test]
    fn discovery_saves_and_loads_the_file() {
        let _lock = crate::test_fs_lock();
        let dir = std::env::temp_dir().join(format!("netmon-devices-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("devices.json");
        let (mut d, msg) = Discovery::start(Some(path.clone()), None);
        assert!(msg.is_none());
        {
            let mut st = d.state.lock().unwrap();
            let now = Instant::now();
            st.see(&HashMap::new(), "eth0", [0, 1, 2, 3, 4, 5], Ipv4Addr::new(10, 0, 0, 2), true, 100, now);
            st.see(&HashMap::new(), "eth0", [0, 1, 2, 3, 4, 7], Ipv4Addr::new(10, 0, 0, 1), true, 100, now);
            st.devices.get_mut(&[0, 1, 2, 3, 4, 7]).unwrap().this_host = true;
        }
        assert!(d.save(Instant::now(), true).is_none());
        let saved: Vec<Device> = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(saved.len(), 1, "the host itself is not saved");
        drop(d);
        let (mut d, _) = Discovery::start(Some(path.clone()), None);
        let (list, new, _) = d.take();
        assert!(list.unwrap().iter().any(|x| x.mac == [0, 1, 2, 3, 4, 5]));
        assert!(new.is_empty());
        assert!(d.state.lock().unwrap().learn_until.is_none(), "with a file: no learning");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
