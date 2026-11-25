use super::*;
use crate::{
    app::{Action, App, Tab},
    client::Client,
};

/// One key action of a UI, as the TUI loop runs it.
fn act(m: &mut Monitor<Fake>, app: &mut App, action: Action) {
    let mut client = Client::new(m.snapshot(), app);
    ui_act(m, &mut client, app, action);
}

fn ui_act(m: &mut Monitor<Fake>, client: &mut Client, app: &mut App, action: Action) {
    if let Some(req) = client.action(app, action) {
        let msg = m.request(req.clone());
        client.add_packets(m.take_packets());
        client.apply(m.snapshot(), app);
        client.replied(app, &req, msg);
    }
}

/// The UI loop's step after the kernel delivered packets.
fn ui_drain(m: &mut Monitor<Fake>, client: &mut Client, app: &mut App) {
    m.drain_capture(DRAIN_BATCH);
    client.add_packets(m.take_packets());
    client.apply(m.snapshot(), app);
}

fn args(interval_ms: u64, expire_secs: u64) -> Args {
    Args { interval_ms, expire_secs, rules: None, ask: false, guard_ports: Vec::new() }
}

#[test]
fn expiry_uses_clamped_interval() {
    assert_eq!(args(1000, 30).expire_ticks(), 30);
    // 10 ms is clamped to 100 ms: 30 s are 300 ticks, not 3000.
    assert_eq!(args(10, 30).expire_ticks(), 300);
    assert_eq!(args(5000, 1).expire_ticks(), 1);
    assert_eq!(args(0, 30).interval(), Duration::from_millis(100));
}

use std::collections::VecDeque;

use netmon_common::{CAPTURE_LEN, FlowStats, IPPROTO_TCP, PacketEvent, RULE_EXE, RULE_NET, RULE_PORT, RULE_PROTO, RuleEntry};

use crate::ifaces::Iface;

#[derive(Debug, PartialEq)]
enum Mode {
    Off,
    Iface(u32),
    Flows(HashSet<netmon_common::FlowKey>),
}

/// Kernel stand-in: counters and a packet ring set by the test.
struct Fake {
    flows: Vec<(netmon_common::FlowKey, FlowStats)>,
    ring: VecDeque<PacketEvent>,
    mode: Mode,
    drops: u64,
    table: Vec<RuleEntry>,
    exe_ids: std::collections::BTreeMap<String, u32>,
    default: u8,
    conns: HashMap<netmon_common::ConnKey, netmon_common::ConnState>,
    names: VecDeque<netmon_common::NameEvent>,
    asks: VecDeque<netmon_common::AskEvent>,
    denies: VecDeque<netmon_common::DenyEvent>,
    verdicts: Vec<(netmon_common::ConnKey, u8)>,
    fail_block: bool,
    fail_capture: bool,
    marked: Vec<(u32, u32)>,
    blocked: HashSet<std::net::IpAddr>,
    limits: Vec<(u32, u64, u64)>,
    sni: HashMap<u64, u8>,
}

impl Kernel for Fake {
    fn set_sni_blocks(&mut self, names: &HashMap<u64, u8>) -> anyhow::Result<usize> {
        self.sni = names.clone();
        Ok(0)
    }
    fn set_limits(&mut self, limits: &[(u32, u64, u64)]) -> anyhow::Result<()> {
        self.limits = limits.to_vec();
        Ok(())
    }
    fn set_blocked_addrs(&mut self, add: &[std::net::IpAddr], remove: &[std::net::IpAddr]) -> Vec<std::net::IpAddr> {
        for ip in remove {
            self.blocked.remove(ip);
        }
        self.blocked.extend(add);
        Vec::new()
    }
    fn attach_new(&mut self, _: &[Iface]) -> Vec<String> {
        Vec::new()
    }
    fn attached_count(&self) -> usize {
        1
    }
    fn snapshot(&self) -> Vec<(netmon_common::FlowKey, FlowStats)> {
        self.flows.clone()
    }
    fn capture_iface(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.mode = Mode::Iface(ifindex);
        Ok(())
    }
    fn capture_flows(&mut self, keys: &HashSet<netmon_common::FlowKey>) -> anyhow::Result<()> {
        // A failed update can leave some keys in the kernel map.
        self.mode = Mode::Flows(keys.clone());
        if self.fail_capture {
            anyhow::bail!("map full");
        }
        Ok(())
    }
    fn capture_off(&mut self) -> anyhow::Result<()> {
        self.mode = Mode::Off;
        Ok(())
    }
    fn discard_packets(&mut self) {
        self.ring.clear();
    }
    fn drain_packets(&mut self, max: usize, mut f: impl FnMut(&PacketEvent)) {
        for _ in 0..max {
            let Some(ev) = self.ring.pop_front() else { break };
            f(&ev);
        }
    }
    fn capture_drops(&self) -> u64 {
        self.drops
    }
    fn forget(&mut self, keys: &[netmon_common::FlowKey]) {
        self.flows.retain(|(k, _)| !keys.contains(k));
    }
    fn sock_owner(&self, _: u64) -> Option<netmon_common::SockOwner> {
        None
    }
    fn listeners(&self) -> Vec<(u8, std::net::SocketAddr, netmon_common::SockOwner)> {
        Vec::new()
    }
    fn set_rules(
        &mut self,
        rules: &[RuleEntry],
        exe_ids: &std::collections::BTreeMap<String, u32>,
        default: u8,
    ) -> anyhow::Result<()> {
        if self.fail_block {
            anyhow::bail!("map full");
        }
        self.table = rules.to_vec();
        self.exe_ids = exe_ids.clone();
        self.default = default;
        Ok(())
    }
    fn conn(&self, key: &netmon_common::ConnKey) -> Option<netmon_common::ConnState> {
        self.conns.get(key).copied()
    }
    fn drain_asks(&mut self, max: usize, mut f: impl FnMut(&netmon_common::AskEvent)) {
        for _ in 0..max {
            let Some(ev) = self.asks.pop_front() else { break };
            f(&ev);
        }
    }
    fn drain_denies(&mut self, max: usize, mut f: impl FnMut(&netmon_common::DenyEvent)) {
        for _ in 0..max {
            let Some(ev) = self.denies.pop_front() else { break };
            f(&ev);
        }
    }
    fn set_verdict(&mut self, key: &netmon_common::ConnKey, action: u8) -> anyhow::Result<()> {
        self.verdicts.push((*key, action));
        Ok(())
    }
    fn drain_names(&mut self, max: usize, mut f: impl FnMut(&netmon_common::NameEvent)) {
        for _ in 0..max {
            let Some(ev) = self.names.pop_front() else { break };
            f(&ev);
        }
    }
    fn mark_pids(&mut self, id: u32, pids: &[u32]) -> usize {
        self.marked.extend(pids.iter().map(|p| (id, *p)));
        0
    }
    fn rule_hits(&self, slot: usize) -> u64 {
        slot as u64 + 100
    }
    fn set_guard(&mut self, _: &[rules::GuardEndpoint], _: &[u16]) -> anyhow::Result<()> {
        Ok(())
    }
}

fn key(port: u16) -> netmon_common::FlowKey {
    // TEST-NET-2 addresses and high ports: no real socket matches them.
    let mut k = netmon_common::FlowKey {
        family: 4,
        proto: IPPROTO_TCP,
        local_port: port,
        remote_port: 443,
        ifindex: 2,
        ..Default::default()
    };
    k.local_addr[..4].copy_from_slice(&[198, 51, 100, 2]);
    k.remote_addr[..4].copy_from_slice(&[198, 51, 100, 9]);
    k
}

fn tx(bytes: u64) -> FlowStats {
    FlowStats { tx_bytes: bytes, ..Default::default() }
}

fn packet() -> PacketEvent {
    PacketEvent { ts_ns: 0, ifindex: 2, len: 0, cap_len: 0, ethertype: 0x0800, egress: 1, has_l2: 1, data: [0; CAPTURE_LEN] }
}

fn monitor() -> (Monitor<Fake>, Instant) {
    let fake = Fake {
        flows: Vec::new(),
        ring: VecDeque::new(),
        mode: Mode::Off,
        drops: 0,
        table: Vec::new(),
        exe_ids: Default::default(),
        limits: Vec::new(),
        sni: HashMap::new(),
        default: 0,
        conns: HashMap::new(),
        names: VecDeque::new(),
        asks: VecDeque::new(),
        denies: VecDeque::new(),
        verdicts: Vec::new(),
        fail_block: false,
        fail_capture: false,
        marked: Vec::new(),
        blocked: HashSet::new(),
    };
    let (mut m, _) = Monitor::with_kernel(fake, &args(1000, 30)).unwrap_or_else(|(_, e)| panic!("{e}"));
    let t0 = Instant::now();
    m.last = t0;
    (m, t0)
}

fn secs(t0: Instant, s: u64) -> Instant {
    t0 + Duration::from_secs(s)
}

#[test]
fn a_capture_that_fails_to_start_leaves_none_running() {
    let (mut m, t0) = monitor();
    let owner = Some(Owner::new(4242, "curl"));
    m.probe.flows = vec![(key(50001), tx(10))];
    m.tick_at(secs(t0, 1));
    m.collector.flows.get_mut(&key(50001)).unwrap().owner = owner;
    m.start_capture(Target::Process { pid: 4242, comm: "curl".into() }).unwrap();
    m.probe.fail_capture = true;
    assert!(m.start_capture(Target::Connection { key: key(50001), label: "x".into() }).is_err());
    assert_eq!(m.probe.mode, Mode::Off, "a half-started capture is turned off");
    assert!(!m.capture.as_ref().unwrap().info.running, "the old capture is not running either");
    m.probe.fail_capture = false;
    m.tick_at(secs(t0, 2));
    assert_eq!(m.probe.mode, Mode::Off, "the old process capture does not come back");
    assert_eq!(m.stop_capture(), "no capture running");
}

#[test]
fn pause_freezes_view_and_keeps_rates_right() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(0))];
    m.tick_at(secs(t0, 1));
    let mut app = App::default();
    let mut client = Client::new(m.snapshot(), &mut app);
    app.paused = true;
    m.probe.flows = vec![(key(50001), tx(1000))];
    m.tick_at(secs(t0, 2));
    client.apply(m.snapshot(), &mut app);
    assert_eq!(client.snap.collector.flows[&key(50001)].tx_rate, 0.0, "view frozen");
    assert_eq!(m.collector.flows[&key(50001)].tx_rate, 1000.0, "counting goes on");
    // 60 s paused, 1000 B/s all the time.
    for s in 3..=61 {
        m.probe.flows = vec![(key(50001), tx(1000 * (s - 1)))];
        m.tick_at(secs(t0, s));
    }
    app.paused = false;
    client.apply(m.snapshot(), &mut app);
    assert_eq!(client.snap.collector.flows[&key(50001)].tx_rate, 1000.0, "no spike after resume");
}

#[test]
fn connection_capture_start_stop_and_restart() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    m.tick_at(secs(t0, 1));
    m.probe.drops = 5;
    let mut app = App::default();
    let mut client = Client::new(m.snapshot(), &mut app);
    ui_act(&mut m, &mut client, &mut app, Action::StartCapture(Tab::Connections));
    assert_eq!(app.tab, Tab::Capture, "{}", app.status);
    assert_eq!(m.probe.mode, Mode::Flows(HashSet::from([key(50001)])));

    m.probe.ring.extend([packet(), packet()]);
    m.probe.drops = 7;
    ui_drain(&mut m, &mut client, &mut app);
    let cap = client.capture.as_ref().unwrap();
    assert_eq!((cap.packets.len(), cap.dropped), (2, 2), "drops count from capture start");

    // Stop keeps what is still queued in the ring.
    m.probe.ring.extend([packet(), packet(), packet()]);
    ui_act(&mut m, &mut client, &mut app, Action::StopCapture);
    let cap = client.capture.as_ref().unwrap();
    assert!(!cap.running);
    assert_eq!(cap.packets.len(), 5);
    assert_eq!(app.status, "capture stopped, 5 packets kept");
    assert_eq!(m.probe.mode, Mode::Off);

    // A stopped capture takes no more packets; a new one discards leftovers.
    m.probe.ring.push_back(packet());
    ui_drain(&mut m, &mut client, &mut app);
    assert_eq!(client.capture.as_ref().unwrap().packets.len(), 5);
    app.tab = Tab::Interfaces;
    ui_act(&mut m, &mut client, &mut app, Action::StartCapture(Tab::Interfaces));
    assert_eq!(m.probe.mode, Mode::Iface(2));
    assert!(m.probe.ring.is_empty());
    assert_eq!(client.capture.as_ref().unwrap().packets.len(), 0);
    // Restarting the same target starts a new, empty capture too.
    m.probe.ring.push_back(packet());
    ui_drain(&mut m, &mut client, &mut app);
    app.tab = Tab::Interfaces;
    ui_act(&mut m, &mut client, &mut app, Action::StartCapture(Tab::Interfaces));
    assert_eq!(client.capture.as_ref().unwrap().packets.len(), 0);
}

#[test]
fn process_capture_follows_new_flows_until_stopped() {
    let (mut m, t0) = monitor();
    let owner = Some(Owner::new(4242, "curl"));
    m.probe.flows = vec![(key(50001), tx(10))];
    m.tick_at(secs(t0, 1));
    m.collector.flows.get_mut(&key(50001)).unwrap().owner = owner.clone();
    m.start_capture(Target::Process { pid: 4242, comm: "curl".into() }).unwrap();
    assert_eq!(m.probe.mode, Mode::Flows(HashSet::from([key(50001)])));

    m.probe.flows.push((key(50002), tx(10)));
    m.tick_at(secs(t0, 2));
    m.collector.flows.get_mut(&key(50002)).unwrap().owner = owner;
    m.sync_process_capture().unwrap();
    assert_eq!(m.probe.mode, Mode::Flows(HashSet::from([key(50001), key(50002)])));

    let mut app = App::default();
    act(&mut m, &mut app, Action::StopCapture);
    m.tick_at(secs(t0, 3));
    assert_eq!(m.probe.mode, Mode::Off, "a stopped capture does not restart");
}

#[test]
fn capture_needs_known_owner() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    m.tick_at(secs(t0, 1));
    let mut app = App { tab: Tab::Processes, ..App::default() };
    act(&mut m, &mut app, Action::StartCapture(Tab::Processes));
    assert!(app.status.contains("owner unknown"), "{}", app.status);
    assert!(m.capture.is_none());
}

#[test]
fn block_toggle_and_remove_from_rules_tab() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    m.tick_at(secs(t0, 1));
    let mut app = App::default();
    act(&mut m, &mut app, Action::ToggleBlockRemote);
    assert_eq!(m.probe.table.len(), 1, "{}", app.status);
    assert_eq!((m.probe.table[0].fields, m.probe.table[0].prefix), (RULE_NET, 32));
    assert!(app.status.starts_with("blocked host 198.51.100.9"), "{}", app.status);
    act(&mut m, &mut app, Action::ToggleBlockPort);
    // New blocks go on top.
    let port = m.probe.table[0];
    assert_eq!((port.fields, port.port_lo, port.port_hi), (RULE_PROTO | RULE_PORT, 443, 443));
    m.tick_at(secs(t0, 2));
    // The fake reports 100 + slot hits and never resets. The host rule
    // had 100 hits before the rewrite and now sits in slot 1.
    assert_eq!((m.rules.rules[0].hits, m.rules.rules[1].hits), (100, 201), "hits read every tick");
    // b again unblocks; the port rule keeps its hits across the rewrite.
    act(&mut m, &mut app, Action::ToggleBlockRemote);
    assert_eq!(m.probe.table, vec![port]);
    assert_eq!(m.rules.rules[0].hits_base, 100);
    m.tick_at(secs(t0, 3));
    assert_eq!(m.rules.rules[0].hits, 200);
    // d in the Rules tab removes the selected rule.
    app.on_key(crate::app::Key::Char('5'));
    act(&mut m, &mut app, Action::RemoveRule);
    assert!(m.probe.table.is_empty() && m.rules.rules.is_empty(), "{}", app.status);
}

#[test]
fn connection_log_gets_new_flows_and_denials() {
    let _fs = crate::test_fs_lock();
    let (mut m, t0) = monitor();
    let dir = std::env::temp_dir().join(format!("netmon-connlog-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("connections.log");
    m.conn_log = Some(crate::connlog::ConnLog::new(&path, None));
    // A flow without an owner is logged on its second tick.
    m.probe.flows = vec![(key(40000), tx(100))];
    let mut deny = netmon_common::DenyEvent { tgid: 4_000_000_000, ..Default::default() };
    deny.comm[..4].copy_from_slice(b"bash");
    deny.key.family = 4;
    deny.key.proto = IPPROTO_TCP;
    deny.key.remote_port = 25;
    deny.key.remote_addr[..4].copy_from_slice(&[198, 51, 100, 7]);
    m.probe.denies.push_back(deny);
    m.probe.denies.push_back(deny);
    m.tick_at(secs(t0, 1));
    let got: Vec<_> = crate::connlog::tail(&path, 10).unwrap().into_iter().map(|e| (e.event, e.remote.to_string(), e.port)).collect();
    assert_eq!(got, vec![("denied".to_string(), "198.51.100.7".to_string(), 25)], "two events, one line");
    let e = &crate::connlog::tail(&path, 1).unwrap()[0];
    assert_eq!((e.comm.as_str(), e.exe.as_str()), ("bash", ""), "name from the event: the pid is gone");
    m.probe.flows = vec![(key(40000), tx(200))];
    m.tick_at(secs(t0, 2));
    m.tick_at(secs(t0, 3));
    let got: Vec<_> = crate::connlog::tail(&path, 10).unwrap().into_iter().map(|e| (e.event, e.remote.to_string(), e.port)).collect();
    assert_eq!(got[0], ("new".to_string(), "198.51.100.9".to_string(), 443), "{got:?}");
    assert_eq!(got.len(), 2, "logged once: {got:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn timed_rules_end() {
    let (mut m, _) = monitor();
    let mut app = App::default();
    let mut client = Client::new(m.snapshot(), &mut app);
    m.request(Request::ToggleBlock(rules::BlockTarget::Port(netmon_common::IPPROTO_TCP, 25)));
    let id = m.rules.rules[0].id;
    // t in the Rules tab: 1 hour.
    ui_drain(&mut m, &mut client, &mut app);
    app.on_key(crate::app::Key::Char('5'));
    ui_act(&mut m, &mut client, &mut app, Action::CycleRuleTimer);
    let now = rules::unix_now();
    let until = m.rules.rules[0].until.expect("timer set");
    assert!(until > now + 3500 && until <= now + 3600, "{until} {now}");
    assert!(m.expire_rules(now).is_none(), "not yet");
    assert_eq!(m.probe.table.len(), 1);
    // At the end time the rule goes, from the list and the kernel table.
    let msg = m.expire_rules(until).unwrap();
    assert!(msg.starts_with("rule ended: deny tcp port 25"), "{msg}");
    assert!(m.rules.rules.is_empty() && m.probe.table.is_empty());
    assert_eq!(m.request(Request::SetRuleTimer { id, secs: Some(60) }), "no such rule");
}

#[test]
fn profiles_replace_the_file_rules_and_keep_temporary_ones() {
    let _fs = crate::test_fs_lock();
    rulefile::TRUST_OWN_FILES.with(|t| t.set(true));
    let dir = std::env::temp_dir().join(format!("netmon-profiles-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("profiles")).unwrap();
    let base = dir.join("rules.toml");
    std::fs::write(&base, "[[rule]]\naction = \"deny\"\nport = 25\n\n[[host]]\nname = \"ads.example\"\n").unwrap();
    std::fs::write(dir.join("profiles/home.toml"), "default = \"deny\"\n\n[[rule]]\naction = \"allow\"\nport = 443\n").unwrap();
    std::fs::write(dir.join("profiles/broken.toml"), "[[rule]]\naction = \"maybe\"\n").unwrap();
    let (mut m, _) = monitor();
    let a = Args { rules: Some(base.clone()), ..args(1000, 30) };
    assert!(m.load_rules_file(&a).unwrap().unwrap().starts_with("1 rules from"));
    m.request(Request::ToggleBlock(rules::BlockTarget::Port(IPPROTO_TCP, 9)));
    m.rules.set_temporary(m.rules.rules[0].id);
    let msg = m.request(Request::LoadProfile("home".into()));
    assert!(msg.starts_with("profile home: 1 rules from"), "{msg}");
    let shown: Vec<String> = m.rules.rules.iter().map(|r| r.to_string()).collect();
    assert_eq!(shown, ["deny tcp port 9", "allow port 443"], "temporary rule stays on top");
    assert_eq!((m.rules.default, m.rules.hosts.len(), m.rules.profile.as_str()), (rules::Action::Deny, 0, "home"));
    assert_eq!(std::fs::read_to_string(dir.join("profile")).unwrap(), "home\n");
    assert_eq!(m.rules_path, dir.join("profiles/home.toml"), "s saves into the profile");
    // A broken profile changes nothing.
    let msg = m.request(Request::LoadProfile("broken".into()));
    assert!(msg.contains("no file rules loaded") && m.rules.profile == "home", "{msg}");
    assert!(m.request(Request::LoadProfile("../etc".into())).contains("use a-z"));
    // Back to the default: the file at start, and no remembered profile.
    let msg = m.request(Request::LoadProfile("default".into()));
    assert!(msg.starts_with("profile default: 1 rules from"), "{msg}");
    assert_eq!((m.rules.default, m.rules.hosts.len(), m.rules.profile.as_str()), (rules::Action::Allow, 1, ""));
    assert!(!dir.join("profile").exists());
    assert_eq!(crate::client::list_profiles(&dir.join("profiles")), ["default", "broken", "home"]);
    rulefile::TRUST_OWN_FILES.with(|t| t.set(false));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rules_file_owned_by_a_user_is_refused() {
    let _fs = crate::test_fs_lock();
    let (mut m, _) = monitor();
    let dir = std::env::temp_dir().join(format!("netmon-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("rules.toml");
    std::fs::write(&path, "[[rule]]\naction = \"deny\"\nport = 25\n").unwrap();
    let a = Args { rules: Some(path.clone()), ..args(1000, 30) };
    let msg = m.load_rules_file(&a).unwrap_err();
    std::fs::remove_dir_all(&dir).unwrap();
    // Tests run as a normal user, so the file is not root's.
    assert!(msg.contains("not owned by root") && msg.contains("no file rules loaded"), "{msg}");
    assert!(m.rules.rules.is_empty());
    let missing = Args { rules: Some(dir.join("gone.toml")), ..args(1000, 30) };
    assert!(m.load_rules_file(&missing).unwrap_err().contains("no file rules loaded"), "explicit path must exist");
}

#[test]
fn kernel_verdicts_read_while_rules_are_in_force() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    let st = netmon_common::ConnState { dir: netmon_common::DIR_IN, action: netmon_common::ACTION_DENY, ..Default::default() };
    m.probe.conns.insert(netmon_common::ConnKey::from_flow(&key(50001)), st);
    m.tick_at(secs(t0, 1));
    assert_eq!(m.collector.flows[&key(50001)].conn, None, "no rules: not read");
    m.rules.default = rules::Action::Deny;
    m.tick_at(secs(t0, 2));
    assert_eq!(m.collector.flows[&key(50001)].conn, Some(st));
    let mut app = App::default();
    act(&mut m, &mut app, Action::ToggleBlockPort);
    assert_eq!(m.probe.default, netmon_common::ACTION_DENY, "default sent with the table");
}

#[test]
fn blocked_hostnames_reach_the_kernel_and_leave_it() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    m.tick_at(secs(t0, 1));
    // An answer for example.com before the block: the block finds it.
    let mut dns = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    dns.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    dns.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 9]);
    let mut ev = netmon_common::NameEvent {
        key: key(53),
        len: dns.len() as u16,
        kind: netmon_common::NAME_DNS,
        _pad: 0,
        data: [0; netmon_common::NAME_DATA],
    };
    ev.data[..dns.len()].copy_from_slice(&dns);
    m.probe.names.push_back(ev);
    m.tick_at(secs(t0, 2));
    assert!(m.probe.blocked.is_empty());
    let ip: std::net::IpAddr = "198.51.100.9".parse().unwrap();
    let msg = m.request(Request::BlockHost { pattern: "*.Example.com".into(), comment: String::new() });
    assert!(msg.starts_with("blocked host *.example.com"), "{msg}");
    assert_eq!(m.probe.blocked, HashSet::from([ip]));
    assert_eq!(m.rules.hosts[0].addrs, vec![ip]);
    // A new answer while the block holds goes to the kernel at once,
    // without a tick.
    let mut dns2 = vec![0, 2, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    dns2.extend_from_slice(b"\x03cdn\x07example\x03com\x00\x00\x01\x00\x01");
    dns2.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 5]);
    ev.len = dns2.len() as u16;
    ev.data = [0; netmon_common::NAME_DATA];
    ev.data[..dns2.len()].copy_from_slice(&dns2);
    m.probe.names.push_back(ev);
    assert!(m.poll_names(secs(t0, 2)));
    assert!(m.probe.blocked.contains(&"203.0.113.5".parse().unwrap()));
    let text = rulefile::render(&m.rules);
    assert!(text.contains("[[host]]\nname = \"*.example.com\""), "{text}");
    let id = m.rules.hosts[0].id;
    assert!(m.request(Request::RemoveHost(id)).starts_with("unblocked host"));
    assert!(m.probe.blocked.is_empty(), "the addresses leave the kernel");
}

#[test]
fn blocklists_block_names_below_their_entries() {
    let (mut m, t0) = monitor();
    let names: HashSet<String> = ["example.com".to_string()].into();
    m.rules.add_blocklist("/etc/netmon/lists/test.txt", "test", Ok((names, 2))).unwrap();
    m.rules.add_blocklist("/etc/netmon/lists/gone.txt", "", Err("No such file or directory".into())).unwrap();
    assert!(m.rules.has_host_blocks());
    // An answer for cdn.example.com: below a listed name, so blocked at once.
    let mut dns = vec![0, 2, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    dns.extend_from_slice(b"\x03cdn\x07example\x03com\x00\x00\x01\x00\x01");
    dns.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 5]);
    let mut ev = netmon_common::NameEvent {
        key: key(53),
        len: dns.len() as u16,
        kind: netmon_common::NAME_DNS,
        _pad: 0,
        data: [0; netmon_common::NAME_DATA],
    };
    ev.data[..dns.len()].copy_from_slice(&dns);
    m.probe.names.push_back(ev);
    assert!(m.poll_names(secs(t0, 1)));
    let ip: std::net::IpAddr = "203.0.113.5".parse().unwrap();
    assert_eq!(m.probe.blocked, HashSet::from([ip]));
    assert_eq!((m.rules.blocklists[0].addrs, m.rules.blocklists[1].addrs), (1, 0));
    // The names never go to the UI; the counts do.
    let snap = serde_json::to_string(&m.snapshot()).unwrap();
    assert!(!snap.contains("\"example.com\"") && snap.contains("\"count\":1"), "{snap}");
    let text = rulefile::render(&m.rules);
    assert!(text.contains("[[blocklist]]\npath = \"/etc/netmon/lists/test.txt\"\ncomment = \"test\"\n"), "{text}");
    assert_eq!(rulefile::parse(&text).unwrap().blocklists.len(), 2);
    // d removes the list, and its addresses leave the kernel.
    let id = m.rules.blocklists[0].id;
    assert!(m.request(Request::RemoveHost(id)).starts_with("removed blocklist /etc/netmon/lists/test.txt"));
    assert!(m.probe.blocked.is_empty());
    // A reload reads the files again: here they do not exist.
    let msg = m.request(Request::ReloadBlocklists);
    assert!(msg.contains("/etc/netmon/lists/gone.txt failed"), "{msg}");
}

#[test]
fn dns_answers_name_flows() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    // Answer for example.com: A 198.51.100.9, the flows' remote address.
    let mut dns = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    dns.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    dns.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 9]);
    let mut ev = netmon_common::NameEvent {
        key: key(53),
        len: dns.len() as u16,
        kind: netmon_common::NAME_DNS,
        _pad: 0,
        data: [0; netmon_common::NAME_DATA],
    };
    ev.data[..dns.len()].copy_from_slice(&dns);
    m.probe.names.push_back(ev);
    m.tick_at(secs(t0, 1));
    assert_eq!(m.collector.flows[&key(50001)].host.as_deref(), Some("example.com"));
    assert_eq!(m.collector.flows[&key(50001)].host_source, "dns");
    let mut app = App::default();
    let rows = app.conn_rows(&m.collector, &m.names);
    assert_eq!(rows[0].remote, "example.com:443");
    assert_eq!(rows[0].remote_addr, "198.51.100.9:443");
    app.on_key(crate::app::Key::Char('h'));
    assert_eq!(app.conn_rows(&m.collector, &m.names)[0].remote, "198.51.100.9:443", "h shows addresses");

    // A ClientHello on this connection names it by SNI, over DNS.
    let mut hello = vec![0x16, 0x03, 0x01, 0, 0, 0x01, 0, 0, 0, 3, 3];
    hello.extend_from_slice(&[0; 32]);
    hello.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    let sni = b"cdn.example.net";
    let ext_len = (9 + sni.len()) as u16;
    hello.extend_from_slice(&ext_len.to_be_bytes());
    hello.extend_from_slice(&[0, 0]);
    hello.extend_from_slice(&((5 + sni.len()) as u16).to_be_bytes());
    hello.extend_from_slice(&((3 + sni.len()) as u16).to_be_bytes());
    hello.push(0);
    hello.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    hello.extend_from_slice(sni);
    let mut ev = netmon_common::NameEvent {
        key: key(50001),
        len: hello.len() as u16,
        kind: netmon_common::NAME_TLS,
        _pad: 0,
        data: [0; netmon_common::NAME_DATA],
    };
    ev.data[..hello.len()].copy_from_slice(&hello);
    m.probe.names.push_back(ev);
    m.tick_at(secs(t0, 2));
    let f = &m.collector.flows[&key(50001)];
    assert_eq!((f.host.as_deref(), f.host_source), (Some("cdn.example.net"), "tls"));
    // The connection expires: its name goes with it.
    m.probe.flows.clear();
    for s in 3..40 {
        m.tick_at(secs(t0, s));
    }
    assert!(m.sni.is_empty());
}

#[test]
fn ask_answers_once_or_by_rule() {
    use crate::app::Answer;
    let (mut m, t0) = monitor();
    let me = std::process::id();
    let conn = |port, rport| netmon_common::ConnKey {
        local_port: port,
        remote_port: rport,
        ..netmon_common::ConnKey::from_flow(&key(443))
    };
    let ask = |k| netmon_common::AskEvent { key: k, tgid: me, _pad: 0 };
    let (k1, k2, k3) = (conn(40000, 443), conn(40001, 443), conn(40002, 80));
    for k in [k1, k2, k3] {
        m.probe.asks.push_back(ask(k));
    }
    m.poll_asks(t0);
    assert_eq!(m.asks.pending.len(), 1, "one question per program");
    assert_eq!(m.asks.pending[0].dests.len(), 2);
    assert!(!m.asks.pending[0].exe.is_empty(), "exe of this test process");
    let mut app = App::default();

    // o: only the selected destination (port 443, two connections), once.
    act(&mut m, &mut app, Action::Answer(Answer::Once { allow: true }));
    assert_eq!(m.probe.verdicts, vec![(k1, netmon_common::ACTION_ALLOW), (k2, netmon_common::ACTION_ALLOW)]);
    assert_eq!(m.asks.pending[0].dests.len(), 1, "port 80 still waits");
    // A second UI answering the same destination late changes nothing.
    let q = m.asks.pending[0].id;
    let dest = crate::proto::DestId { remote: crate::ask::remote(&k1), port: 443, proto: k1.proto };
    let late = Request::Answer { question: q, dest, scope: ask::Scope::Program, answer: Answer::Once { allow: false } };
    assert_eq!(m.request(late), "destination already answered");
    let gone = Request::Answer { question: q + 1, dest, scope: ask::Scope::Program, answer: Answer::Once { allow: false } };
    assert_eq!(m.request(gone), "question already answered or timed out");
    assert_eq!(m.probe.verdicts.len(), 2);

    // d with port scope: a temporary deny rule; the question is decided.
    act(&mut m, &mut app, Action::AskScope(1));
    act(&mut m, &mut app, Action::Answer(Answer::Rule { allow: false, always: false }));
    assert!(m.asks.pending.is_empty(), "{}", app.status);
    let r = &m.rules.rules[0];
    assert_eq!((r.action, r.temporary, r.m.ports), (rules::Action::Deny, true, Some((80, 80))));
    assert_eq!(m.probe.table.len(), 1, "rule in the kernel");
    assert!(!rulefile::render(&m.rules).contains("[[rule]]"), "temporary rules are not saved");

    // A with program scope: always; later connections of it are decided.
    m.probe.asks.push_back(ask(conn(40003, 8443)));
    m.poll_asks(t0);
    act(&mut m, &mut app, Action::Answer(Answer::Rule { allow: true, always: true }));
    assert!(m.asks.pending.is_empty());
    // Events queued before the answer do not bring the question back.
    m.probe.asks.push_back(ask(conn(40005, 8443)));
    m.probe.asks.push_back(ask(conn(40006, 9000)));
    m.poll_asks(t0);
    assert!(m.asks.pending.is_empty(), "the program rule decides them");
    assert!(rulefile::render(&m.rules).contains("action = \"allow\""));

    // A question nobody answers is denied after the timeout.
    // Unknown process: no program rule, but port and destination work.
    let unknown = netmon_common::AskEvent { key: conn(40004, 22), tgid: 0, _pad: 0 };
    m.probe.asks.push_back(unknown);
    m.poll_asks(t0);
    assert_eq!(m.asks.pending[0].comm, "unknown process");
    act(&mut m, &mut app, Action::AskScope(-1));
    act(&mut m, &mut app, Action::Answer(Answer::Rule { allow: true, always: false }));
    assert!(app.status.contains("process unknown"), "{}", app.status);
    act(&mut m, &mut app, Action::AskScope(1));
    act(&mut m, &mut app, Action::Answer(Answer::Rule { allow: true, always: false }));
    assert!(m.asks.pending.is_empty(), "{}", app.status);
    assert_eq!(m.rules.rules[0].m.to_string(), "out tcp port 22");
    let unknown = netmon_common::AskEvent { key: conn(40007, 23), tgid: 0, _pad: 0 };
    m.probe.asks.push_back(unknown);
    m.poll_asks(t0);
    m.poll_asks(t0 + ask::ASK_TIMEOUT);
    assert_eq!(m.probe.verdicts.last(), Some(&(unknown.key, netmon_common::ACTION_DENY)));
    assert!(m.asks.pending.is_empty());
}

#[test]
fn failed_block_leaves_no_rule() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    m.tick_at(secs(t0, 1));
    m.probe.fail_block = true;
    let mut app = App::default();
    act(&mut m, &mut app, Action::ToggleBlockRemote);
    assert!(app.status.contains("rule update failed"), "{}", app.status);
    assert!(m.rules.rules.is_empty());
}

#[test]
fn process_block_marks_running_pids_by_exe() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    m.tick_at(secs(t0, 1));
    // This test process is a running process with a known exe.
    let me = std::env::current_exe().unwrap().to_string_lossy().into_owned();
    let pid = std::process::id();
    let f = m.collector.flows.get_mut(&key(50001)).unwrap();
    f.owner = Some(crate::procmap::Owner {
        details: Some(crate::procmap::ProcDetails { exe: me.clone(), ..Default::default() }),
        ..Owner::new(pid, "test")
    });
    let mut app = App { tab: Tab::Processes, ..App::default() };
    act(&mut m, &mut app, Action::ToggleBlockProcess);
    assert_eq!((m.probe.table[0].fields, m.probe.table[0].exe), (RULE_EXE, 1), "{}", app.status);
    assert_eq!(m.probe.exe_ids.get(&me), Some(&1));
    assert!(m.probe.marked.contains(&(1, pid)), "running pid marked at once");
}

#[test]
fn snapshot_and_requests_survive_json() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    m.tick_at(secs(t0, 1));
    let f = m.collector.flows.get_mut(&key(50001)).unwrap();
    f.owner = Some(Owner { container: Some("web".into()), ..Owner::new(7, "curl") });
    f.state = "ESTAB";
    f.host = Some("example.com".into());
    f.host_source = "tls";
    m.toggle_block(BlockTarget::Exe("/usr/bin/curl".into()));
    let k = netmon_common::ConnKey::from_flow(&key(50001));
    m.probe.asks.push_back(netmon_common::AskEvent { key: k, tgid: std::process::id(), _pad: 0 });
    m.poll_asks(t0);
    m.start_capture(Target::Connection { key: key(50001), label: "x".into() }).unwrap();
    m.probe.ring.push_back(PacketEvent { cap_len: 3, data: [7; CAPTURE_LEN], ..packet() });
    m.drain_capture(DRAIN_BATCH);

    let snap = m.snapshot();
    let json = serde_json::to_string(&snap).unwrap();
    let back: Snapshot = serde_json::from_str(&json).unwrap();
    let (a, b) = (&snap.collector.flows[&key(50001)], &back.collector.flows[&key(50001)]);
    assert_eq!((&a.owner, a.state, &a.host, a.host_source), (&b.owner, b.state, &b.host, b.host_source));
    assert_eq!(back.collector.flows.len(), 1);
    assert_eq!(back.names.get(2), snap.names.get(2));
    assert_eq!(back.rules.rules, snap.rules.rules);
    assert_eq!(back.rules.exe_ids(), snap.rules.exe_ids());
    let same_since = |mut p: ask::Prompt| {
        p.since = t0;
        p
    };
    assert_eq!(back.questions.iter().cloned().map(same_since).collect::<Vec<_>>(), snap.questions.iter().cloned().map(same_since).collect::<Vec<_>>());
    let drift = back.questions[0].since.saturating_duration_since(snap.questions[0].since);
    assert!(drift < Duration::from_secs(1), "age kept, to the millisecond: {drift:?}");
    assert_eq!(back.capture, snap.capture);

    let packets = m.take_packets();
    let json = serde_json::to_string(&packets).unwrap();
    assert!(json.contains("\"data\":\"BwcH\""), "bytes as base64: {json}");
    assert_eq!(serde_json::from_str::<Vec<RawPacket>>(&json).unwrap(), packets);

    let q = &snap.questions[0];
    for req in [
        Request::ToggleBlock(BlockTarget::host("192.0.2.1".parse().unwrap())),
        Request::ToggleBlock(BlockTarget::Port(6, 25)),
        Request::RemoveRule(3),
        Request::SaveRules,
        Request::Answer {
            question: q.id,
            dest: (&q.dests[0]).into(),
            scope: ask::Scope::Port,
            answer: crate::app::Answer::Rule { allow: true, always: false },
        },
        Request::StartCapture(Target::Process { pid: 7, comm: "curl".into() }),
        Request::StopCapture,
    ] {
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), req, "{json}");
    }
}

#[test]
fn engine_orders_messages_and_ticks_on_time() {
    use crate::{engine::Engine, proto::ToClient};
    let (mut m, _) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    let mut e = Engine::new(m, Duration::from_secs(1));
    assert_eq!(e.mon.collector.flows.len(), 1, "first sample at start");
    let kinds = |msgs: &[ToClient]| {
        msgs.iter()
            .map(|m| match m {
                ToClient::Snapshot(_) => "snapshot",
                ToClient::Packets(_) => "packets",
                ToClient::Reply { .. } => "reply",
                ToClient::Status(_) => "status",
                _ => "other",
            })
            .collect::<Vec<_>>()
    };
    let req = Request::ToggleBlock(BlockTarget::Port(6, 25));
    let out = e.request(req.clone());
    assert_eq!(kinds(&out), ["snapshot", "reply"]);
    match &out[1] {
        ToClient::Reply { req: r, msg } => assert_eq!((r, msg.starts_with("blocked")), (&req, true), "{msg}"),
        _ => unreachable!(),
    }
    let now = Instant::now();
    assert!(e.step(now).is_empty(), "nothing due");
    assert!(e.wait() <= Duration::from_secs(1));
    assert_eq!(kinds(&e.step(now + Duration::from_secs(1))), ["snapshot"], "tick due");
    // Far behind: one tick, not a burst to catch up.
    assert_eq!(kinds(&e.step(now + Duration::from_secs(60))), ["snapshot"]);
    assert!(e.step(now + Duration::from_millis(60_500)).is_empty());
}

#[test]
fn container_tables_read_once_per_new_unowned_flow() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(50001), tx(10))];
    m.tick_at(secs(t0, 1));
    assert_eq!(m.containers_asked, Some(secs(t0, 1)), "new flow without owner");
    m.probe.flows = vec![(key(50001), tx(20))];
    m.tick_at(secs(t0, 10));
    assert_eq!(m.containers_asked, Some(secs(t0, 1)), "same flow: not again");
    m.probe.flows = vec![(key(50001), tx(30)), (key(50002), tx(10))];
    m.tick_at(secs(t0, 20));
    assert_eq!(m.containers_asked, Some(secs(t0, 20)), "another new flow");
}

#[test]
fn asks_without_process_read_container_tables_once_per_connection() {
    let (mut m, t0) = monitor();
    let k = netmon_common::ConnKey::from_flow(&key(50001));
    let ask = |key| netmon_common::AskEvent { key, tgid: 0, _pad: 0 };
    m.probe.asks.push_back(ask(k));
    m.poll_asks(secs(t0, 1));
    assert_eq!(m.containers_asked, Some(secs(t0, 1)));
    // A retransmit of the same connection: no new read.
    m.probe.asks.push_back(ask(k));
    m.poll_asks(secs(t0, 3));
    assert_eq!(m.containers_asked, Some(secs(t0, 1)));
    m.probe.asks.push_back(ask(netmon_common::ConnKey { local_port: 50002, ..k }));
    m.poll_asks(secs(t0, 4));
    assert_eq!(m.containers_asked, Some(secs(t0, 4)), "a new connection");
}

#[test]
fn failed_rule_edit_leaves_nothing_behind() {
    let (mut m, _) = monitor();
    let msg = m.change_rules(|r| {
        r.default = rules::Action::Deny;
        r.insert(usize::MAX, rules::Action::Deny, BlockTarget::Port(6, 25).into(), "")?;
        r.insert(usize::MAX, rules::Action::Deny, BlockTarget::Port(6, 25).into(), "").map(|_| String::new())
    });
    assert!(msg.contains("already exists"), "{msg}");
    assert!(m.rules.rules.is_empty(), "the first rule of the failed edit is gone");
    assert_eq!(m.rules.default, rules::Action::Allow, "and the default too");
    assert!(m.probe.table.is_empty());
    // The next change does not carry the failed edit into the kernel.
    m.toggle_block(BlockTarget::Port(17, 53));
    assert_eq!((m.rules.rules.len(), m.probe.default), (1, netmon_common::ACTION_ALLOW));
}

#[test]
fn rule_the_kernel_could_not_match_yet_decides_without_a_question() {
    let (mut m, t0) = monitor();
    let me = std::fs::read_link("/proc/self/exe").unwrap().to_string_lossy().into_owned();
    m.change_rules(|r| {
        let m = rules::Match { exe: Some(me.clone()), dir: Some(rules::Dir::Out), ..Default::default() };
        r.insert(0, rules::Action::Allow, m, "").map(|_| String::new())
    });
    let k = netmon_common::ConnKey::from_flow(&key(50001));
    m.probe.asks.push_back(netmon_common::AskEvent { key: k, tgid: std::process::id(), _pad: 0 });
    m.poll_asks(t0);
    assert!(m.asks.pending.is_empty(), "no question");
    assert_eq!(m.probe.verdicts, vec![(k, netmon_common::ACTION_ALLOW)], "the rule's verdict, not a hang");
}

#[test]
fn connections_beyond_the_question_limit_are_denied_not_lost() {
    let (mut m, t0) = monitor();
    let k = netmon_common::ConnKey::from_flow(&key(50001));
    for port in 0..=256u16 {
        let key = netmon_common::ConnKey { local_port: 10_000 + port, ..k };
        m.probe.asks.push_back(netmon_common::AskEvent { key, tgid: std::process::id(), _pad: 0 });
    }
    // ASK_BATCH events per poll.
    m.poll_asks(t0);
    m.poll_asks(t0);
    assert_eq!(m.asks.pending[0].conns(), 256);
    assert_eq!(m.probe.verdicts, vec![(netmon_common::ConnKey { local_port: 10_256, ..k }, netmon_common::ACTION_DENY)]);
}

#[test]
fn a_question_of_several_containers_gets_no_single_name() {
    use crate::procmap::{ContainerTable, RawSock};
    let (mut m, t0) = monitor();
    let k1 = netmon_common::ConnKey::from_flow(&key(50001));
    let k2 = netmon_common::ConnKey { local_port: 50002, ..k1 };
    for k in [k1, k2] {
        m.probe.asks.push_back(netmon_common::AskEvent { key: k, tgid: 0, _pad: 0 });
    }
    m.poll_asks(t0);
    assert_eq!((m.asks.pending.len(), m.asks.pending[0].comm.as_str()), (1, "unknown process"));
    let sock = |port: u16, inode| RawSock {
        proto: 6,
        local: format!("172.17.0.2:{port}").parse().unwrap(),
        remote: "198.51.100.9:443".parse().unwrap(),
        state: "",
        inode,
    };
    let owners = HashMap::from([(1, Owner::new(11, "curl")), (2, Owner::new(22, "wget"))]);
    m.containers = vec![
        ContainerTable::build("web", vec![sock(50001, 1)], &owners),
        ContainerTable::build("db", vec![sock(50002, 2)], &owners),
    ];
    m.poll_asks(t0);
    assert_eq!(m.asks.pending[0].comm, SEVERAL, "not the first container's name");
    assert_eq!(m.asks.pending[0].pid, 0);
}

#[test]
fn dns_log_names_the_asking_program_and_marks_blocked_names() {
    let (mut m, t0) = monitor();
    m.probe.flows = vec![(key(53), tx(10))];
    m.tick_at(secs(t0, 1));
    m.collector.flows.get_mut(&key(53)).unwrap().owner = Some(Owner::new(4242, "curl"));
    m.rules.add_blocklist("/etc/netmon/lists/test.txt", "test", Ok((["example.com".to_string()].into(), 1))).unwrap();
    let mut dns = vec![0, 2, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    dns.extend_from_slice(b"\x03cdn\x07example\x03com\x00\x00\x01\x00\x01");
    dns.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 5]);
    let mut ev = netmon_common::NameEvent {
        key: key(53),
        len: dns.len() as u16,
        kind: netmon_common::NAME_DNS,
        _pad: 0,
        data: [0; netmon_common::NAME_DATA],
    };
    ev.data[..dns.len()].copy_from_slice(&dns);
    m.probe.names.push_back(ev);
    // Read between ticks (host blocks exist), logged at the next tick.
    assert!(m.poll_names(secs(t0, 1)));
    assert!(m.dns_log.is_empty());
    m.tick_at(secs(t0, 2));
    let e = m.dns_log.back().unwrap();
    assert_eq!((e.program.as_str(), e.pid, e.name.as_str(), e.qtype.as_str()), ("curl", Some(4242), "cdn.example.com", "A"));
    assert_eq!(e.answers, vec!["203.0.113.5"]);
    assert!(e.blocked);
    assert_eq!(e.result(), "203.0.113.5");
    assert_eq!(m.new_dns.len(), 1);
}

#[test]
fn limits_reach_the_kernel_with_exe_ids_and_go_again() {
    let (mut m, _) = monitor();
    let msg = m.request(Request::SetLimit { exe: "/usr/bin/curl".into(), up_mb: Some(1.0), down_mb: Some(5.0) });
    assert_eq!(msg, "limit ↓5 ↑1 MB/s for /usr/bin/curl");
    assert_eq!(m.probe.limits, vec![(1, 1_000_000, 5_000_000)]);
    assert_eq!(m.probe.exe_ids.get("/usr/bin/curl"), Some(&1), "the exe id is in the kernel first");
    assert!(m.request(Request::SetLimit { exe: "rel".into(), up_mb: Some(1.0), down_mb: None }).contains("absolute path"));
    assert_eq!(m.probe.limits.len(), 1, "a refused limit changes nothing");
    m.request(Request::SetLimit { exe: "/usr/bin/curl".into(), up_mb: None, down_mb: None });
    assert!(m.probe.limits.is_empty() && m.probe.exe_ids.is_empty());
    assert_eq!(crate::client::next_limit(None), Some(1.0));
    assert_eq!(crate::client::next_limit(Some(20.0)), None);
    assert_eq!(crate::client::next_limit(Some(3.0)), None);
}

#[test]
fn learned_allow_rules_go_to_the_end() {
    let (mut m, _) = monitor();
    m.request(Request::ToggleBlock(BlockTarget::Exe("/usr/bin/nc".into())));
    let rule = |port: u16| {
        (crate::rules::Match { exe: Some("/usr/bin/curl".into()), ports: Some((port, port)), ..Default::default() }, format!("learned {port}"))
    };
    let msg = m.request(Request::AddAllowRules(vec![rule(80), rule(443)]));
    assert_eq!(msg, "2 allow rules added at the end; s saves them");
    let r = &m.rules.rules;
    assert_eq!(r.len(), 3);
    assert_eq!((r[0].action, r[2].action, r[2].comment.as_str()), (rules::Action::Deny, rules::Action::Allow, "learned 443"));
    assert_eq!(m.probe.table.len(), 3);
    // All or none: a bad rule adds nothing.
    let bad = (crate::rules::Match { exe: Some("rel".into()), ..Default::default() }, String::new());
    assert!(m.request(Request::AddAllowRules(vec![rule(8080), bad])).contains("absolute path"));
    assert_eq!(m.rules.rules.len(), 3);
}

#[test]
fn host_blocks_reach_the_kernel_server_name_check() {
    let (mut m, _) = monitor();
    m.request(Request::BlockHost { pattern: "*.doubleclick.net".into(), comment: String::new() });
    let k = netmon_common::sni_hash("doubleclick.net");
    assert_eq!(m.probe.sni.get(&k), Some(&(netmon_common::SNI_SELF | netmon_common::SNI_BELOW)));
    let id = m.rules.hosts[0].id;
    m.request(Request::RemoveHost(id));
    assert!(m.probe.sni.is_empty());
}
