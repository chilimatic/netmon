//! UI state and the row models for each tab. No rendering here.

use std::collections::HashMap;

use netmon_common::{FlowKey, IPPROTO_TCP, IPPROTO_UDP};

use crate::{
    collector::{Collector, Flow},
    ifaces::Names,
    procmap::{Owner, ProcDetails},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Connections,
    Processes,
    Interfaces,
    Capture,
    Rules,
}

impl Tab {
    pub const ALL: [Tab; 5] = [Tab::Connections, Tab::Processes, Tab::Interfaces, Tab::Capture, Tab::Rules];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Connections => "Connections",
            Tab::Processes => "Processes",
            Tab::Interfaces => "Interfaces",
            Tab::Capture => "Capture",
            Tab::Rules => "Rules",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    fn prev(self) -> Tab {
        Tab::ALL[(self.index() + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }

    fn next(self) -> Tab {
        Tab::ALL[(self.index() + 1) % Tab::ALL.len()]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Rate,
    Total,
    Process,
}

/// Identity of a table row. The selection follows it when rows re-sort.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowId {
    Conn(FlowKey),
    Proc(String, String),
    Iface(u32),
    Rule(u32),
}

pub struct ConnRow {
    pub key: FlowKey,
    pub process: String,
    pub pid: String,
    /// Exe path, user, unit; empty when unknown.
    pub exe: String,
    pub user: String,
    pub unit: String,
    /// Where the owner came from: "kernel", "/proc" or "".
    pub source: &'static str,
    pub proto: &'static str,
    pub local: String,
    pub remote: String,
    pub iface: String,
    pub state: &'static str,
    pub tx_rate: f64,
    pub rx_rate: f64,
    pub total: u64,
    /// Direction and verdict from the kernel's connection state.
    pub conn: Option<netmon_common::ConnState>,
    /// Hostname of the remote end, if known, and where it came from.
    pub host: Option<String>,
    pub host_source: &'static str,
    /// Remote address and port, also when `remote` shows the hostname.
    pub remote_addr: String,
}

pub struct ProcRow {
    pub pid_num: Option<u32>,
    pub process: String,
    pub pid: String,
    pub user: String,
    pub exe: String,
    pub conns: usize,
    pub tx_rate: f64,
    pub rx_rate: f64,
    pub total: u64,
}

pub struct IfaceRow {
    pub index: u32,
    pub name: String,
    pub kind: &'static str,
    pub tx_rate: f64,
    pub rx_rate: f64,
    pub total: u64,
}

impl ConnRow {
    pub fn id(&self) -> RowId {
        RowId::Conn(self.key)
    }
}

impl ProcRow {
    pub fn id(&self) -> RowId {
        RowId::Proc(self.process.clone(), self.pid.clone())
    }
}

impl IfaceRow {
    pub fn id(&self) -> RowId {
        RowId::Iface(self.index)
    }
}

pub struct App {
    pub tab: Tab,
    pub sort: Sort,
    pub filter: String,
    pub editing_filter: bool,
    pub paused: bool,
    pub show_graph: bool,
    /// Remote column shows hostnames where known.
    pub show_hosts: bool,
    /// Connections also lists rows of bridges and veth/vlan interfaces,
    /// which repeat traffic of other interfaces.
    pub show_virtual: bool,
    /// The question shown in ask mode and how many more wait. Set by the
    /// main loop; while set, a and d answer it.
    pub ask: Option<(crate::ask::Prompt, usize)>,
    /// Seconds between samples, for the graph's time axis.
    pub interval_secs: f64,
    /// Index of the selected row as last drawn.
    pub selected: usize,
    /// The selected row. Wins over `selected` when the row still exists.
    pub anchor: Option<RowId>,
    /// Cursor moves not yet applied; applied relative to `anchor`.
    pub pending: isize,
    pub quit: bool,
    pub status: String,
}

impl Default for App {
    fn default() -> Self {
        App {
            tab: Tab::Connections,
            sort: Sort::Rate,
            filter: String::new(),
            editing_filter: false,
            paused: false,
            show_graph: true,
            show_hosts: true,
            show_virtual: false,
            ask: None,
            interval_secs: 1.0,
            selected: 0,
            anchor: None,
            pending: 0,
            quit: false,
            status: String::new(),
        }
    }
}

pub enum Key {
    Char(char),
    Backspace,
    Enter,
    Esc,
    Tab,
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
}

/// Work the main loop must do after a key press.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Capture the selected row of `tab` (interface, process or connection).
    StartCapture(Tab),
    StopCapture,
    SavePcap,
    ClearCapture,
    /// Move the capture selection by this many packets.
    MovePacket(isize),
    /// Jump to the oldest (false) or newest (true) packet.
    JumpPacket(bool),
    /// Block (or unblock, if blocked) the remote address of the selected
    /// connection.
    ToggleBlockRemote,
    /// Block (or unblock) the remote port of the selected connection.
    ToggleBlockPort,
    /// Block (or unblock) the exe of the selected process.
    ToggleBlockProcess,
    /// Remove the selected rule in the Rules tab.
    RemoveRule,
    /// Write all rules to the rules file.
    SaveRules,
    /// Answer the shown ask-mode question.
    Answer(Answer),
    /// Select another destination of the shown question.
    AskSelect(isize),
    /// Switch the scope of the shown question.
    AskScope(isize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Answer {
    /// Only the selected destination's waiting connections.
    Once { allow: bool },
    /// A rule for the chosen scope; `always` keeps it (saved with `s`),
    /// otherwise it ends when netmon exits.
    Rule { allow: bool, always: bool },
}

impl App {
    pub fn on_key(&mut self, key: Key) -> Option<Action> {
        if self.editing_filter {
            match key {
                Key::Char(c) => self.filter.push(c),
                Key::Backspace => {
                    self.filter.pop();
                }
                Key::Enter => self.editing_filter = false,
                Key::Esc => {
                    self.filter.clear();
                    self.editing_filter = false;
                }
                _ => {}
            }
            self.reset_selection();
            return None;
        }
        if self.ask.is_some() {
            let rule = |allow, always| Some(Action::Answer(Answer::Rule { allow, always }));
            match key {
                Key::Char('a') => return rule(true, false),
                Key::Char('A') => return rule(true, true),
                Key::Char('d') => return rule(false, false),
                Key::Char('D') => return rule(false, true),
                Key::Char('o') => return Some(Action::Answer(Answer::Once { allow: true })),
                Key::Char('x') => return Some(Action::Answer(Answer::Once { allow: false })),
                Key::Up | Key::Char('k') => return Some(Action::AskSelect(-1)),
                Key::Down | Key::Char('j') => return Some(Action::AskSelect(1)),
                Key::Left => return Some(Action::AskScope(-1)),
                Key::Right => return Some(Action::AskScope(1)),
                _ => {}
            }
        }
        if self.tab == Tab::Capture {
            match key {
                Key::Up | Key::Char('k') => return Some(Action::MovePacket(-1)),
                Key::Down | Key::Char('j') => return Some(Action::MovePacket(1)),
                Key::PageUp => return Some(Action::MovePacket(-20)),
                Key::PageDown => return Some(Action::MovePacket(20)),
                Key::Home => return Some(Action::JumpPacket(false)),
                Key::End | Key::Char('f') => return Some(Action::JumpPacket(true)),
                Key::Char('x') => return Some(Action::StopCapture),
                Key::Char('s') => return Some(Action::SavePcap),
                Key::Char('c') => return Some(Action::ClearCapture),
                _ => {}
            }
        }
        match key {
            Key::Char('q') => self.quit = true,
            // Esc never quits: it only clears an active filter.
            Key::Esc => {
                self.filter.clear();
                self.reset_selection();
            }
            Key::Tab | Key::Right => self.set_tab(self.tab.next()),
            Key::Left => self.set_tab(self.tab.prev()),
            Key::Char('1') => self.set_tab(Tab::Connections),
            Key::Char('2') => self.set_tab(Tab::Processes),
            Key::Char('3') => self.set_tab(Tab::Interfaces),
            Key::Char('4') => self.set_tab(Tab::Capture),
            Key::Char('5') => self.set_tab(Tab::Rules),
            Key::Char('b') if self.tab == Tab::Connections => return Some(Action::ToggleBlockRemote),
            Key::Char('B') if self.tab == Tab::Connections => return Some(Action::ToggleBlockPort),
            Key::Char('b') if self.tab == Tab::Processes => return Some(Action::ToggleBlockProcess),
            Key::Char('d') if self.tab == Tab::Rules => return Some(Action::RemoveRule),
            Key::Char('s') if self.tab == Tab::Rules => return Some(Action::SaveRules),
            Key::Enter if matches!(self.tab, Tab::Connections | Tab::Processes | Tab::Interfaces) => {
                return Some(Action::StartCapture(self.tab));
            }
            Key::Char('r') => self.sort = Sort::Rate,
            Key::Char('t') => self.sort = Sort::Total,
            Key::Char('n') => self.sort = Sort::Process,
            Key::Char('p') | Key::Char(' ') => self.paused = !self.paused,
            Key::Char('/') => self.editing_filter = true,
            Key::Char('g') => self.show_graph = !self.show_graph,
            Key::Char('h') => self.show_hosts = !self.show_hosts,
            Key::Char('v') => {
                self.show_virtual = !self.show_virtual;
                self.reset_selection();
            }
            Key::Up | Key::Char('k') => self.pending -= 1,
            Key::Down | Key::Char('j') => self.pending += 1,
            Key::PageUp => self.pending -= 20,
            Key::PageDown => self.pending += 20,
            Key::Home => self.reset_selection(),
            _ => {}
        }
        None
    }

    fn set_tab(&mut self, tab: Tab) {
        if tab != self.tab {
            self.tab = tab;
            self.reset_selection();
        }
    }

    fn reset_selection(&mut self) {
        self.selected = 0;
        self.anchor = None;
        self.pending = 0;
    }

    /// Index of the selected row in `ids` without changing state.
    pub fn selected_in(&self, ids: &[RowId]) -> Option<usize> {
        if ids.is_empty() {
            return None;
        }
        let base = self.anchor.as_ref().and_then(|a| ids.iter().position(|i| i == a)).unwrap_or(self.selected);
        Some(base.saturating_add_signed(self.pending).min(ids.len() - 1))
    }

    /// Applies pending moves to the rows about to be drawn and anchors the
    /// selection to the row it lands on.
    pub fn sync_selection(&mut self, ids: &[RowId]) -> usize {
        if let Some(i) = self.selected_in(ids) {
            self.selected = i;
            self.anchor = Some(ids[i].clone());
        } else {
            self.selected = 0;
        }
        self.pending = 0;
        self.selected
    }

    fn matches(&self, fields: &[&str]) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let needle = self.filter.to_lowercase();
        fields.iter().any(|f| f.to_lowercase().contains(&needle))
    }

    pub fn conn_rows(&self, c: &Collector, names: &Names) -> Vec<ConnRow> {
        let mut rows: Vec<ConnRow> = c
            .flows
            .values()
            .filter(|f| self.show_virtual || !names.kind(f.key.ifindex).is_virtual())
            .map(|f| conn_row(f, names, self.show_hosts))
            .filter(|r| {
                let host = r.host.as_deref().unwrap_or("");
                self.matches(&[&r.process, &r.pid, &r.exe, &r.user, &r.unit, &r.local, &r.remote, host, &r.iface, r.proto])
            })
            .collect();
        match self.sort {
            Sort::Rate => rows.sort_by(|a, b| (b.tx_rate + b.rx_rate).total_cmp(&(a.tx_rate + a.rx_rate)).then(b.total.cmp(&a.total))),
            Sort::Total => rows.sort_by(|a, b| b.total.cmp(&a.total)),
            Sort::Process => rows.sort_by(|a, b| a.process.cmp(&b.process).then(a.remote.cmp(&b.remote))),
        }
        rows
    }

    pub fn proc_rows(&self, c: &Collector, names: &Names) -> Vec<ProcRow> {
        let mut by: HashMap<(String, String), ProcRow> = HashMap::new();
        // Container flows on veth and bridge repeat the uplink's.
        for f in c.flows.values().filter(|f| self.show_virtual || !names.kind(f.key.ifindex).is_virtual()) {
            let (process, pid) = owner_cols(f);
            let d = details(f);
            let r = by.entry((process.clone(), pid.clone())).or_insert(ProcRow {
                pid_num: f.owner.as_ref().map(|o| o.pid),
                process,
                pid,
                user: d.user.clone(),
                exe: d.exe.clone(),
                conns: 0,
                tx_rate: 0.0,
                rx_rate: 0.0,
                total: 0,
            });
            r.conns += 1;
            r.tx_rate += f.tx_rate;
            r.rx_rate += f.rx_rate;
            r.total += f.total.tx_bytes + f.total.rx_bytes;
        }
        let mut rows: Vec<ProcRow> = by.into_values().filter(|r| self.matches(&[&r.process, &r.pid, &r.user, &r.exe])).collect();
        match self.sort {
            Sort::Rate => rows.sort_by(|a, b| (b.tx_rate + b.rx_rate).total_cmp(&(a.tx_rate + a.rx_rate)).then(b.total.cmp(&a.total))),
            Sort::Total => rows.sort_by(|a, b| b.total.cmp(&a.total)),
            Sort::Process => rows.sort_by(|a, b| a.process.cmp(&b.process)),
        }
        rows
    }

    pub fn iface_rows(&self, c: &Collector, names: &Names) -> Vec<IfaceRow> {
        let mut rows: Vec<IfaceRow> = c
            .ifaces
            .iter()
            .map(|(idx, s)| IfaceRow {
                index: *idx,
                name: names.get(*idx),
                kind: names.kind(*idx).label(),
                tx_rate: s.tx_rate,
                rx_rate: s.rx_rate,
                total: s.tx_total + s.rx_total,
            })
            .filter(|r| self.matches(&[&r.name]))
            .collect();
        match self.sort {
            Sort::Rate => rows.sort_by(|a, b| (b.tx_rate + b.rx_rate).total_cmp(&(a.tx_rate + a.rx_rate)).then(b.total.cmp(&a.total))),
            Sort::Total => rows.sort_by(|a, b| b.total.cmp(&a.total)),
            Sort::Process => rows.sort_by(|a, b| a.name.cmp(&b.name)),
        }
        rows
    }
}

fn owner_cols(f: &Flow) -> (String, String) {
    match &f.owner {
        Some(Owner { container: Some(c), comm, pid, .. }) => (format!("container:{c}/{comm}"), pid.to_string()),
        Some(o) => (o.comm.clone(), o.pid.to_string()),
        None => ("?".into(), "-".into()),
    }
}

static NO_DETAILS: ProcDetails =
    ProcDetails { exe: String::new(), user: String::new(), unit: String::new(), cgroup: String::new() };

fn details(f: &Flow) -> &ProcDetails {
    f.owner.as_ref().and_then(|o| o.details.as_ref()).unwrap_or(&NO_DETAILS)
}

fn conn_row(f: &Flow, names: &Names, show_hosts: bool) -> ConnRow {
    let (process, pid) = owner_cols(f);
    let d = details(f);
    ConnRow {
        key: f.key,
        process,
        pid,
        exe: d.exe.clone(),
        user: d.user.clone(),
        unit: d.unit.clone(),
        source: if f.owner.is_some() { f.owner_source.label() } else { "" },
        proto: match f.key.proto {
            IPPROTO_TCP => "tcp",
            IPPROTO_UDP => "udp",
            1 => "icmp",
            58 => "icmp6",
            _ => "other",
        },
        local: f.local.to_string(),
        remote: match &f.host {
            Some(h) if show_hosts => format!("{h}:{}", f.remote.port()),
            _ => f.remote.to_string(),
        },
        remote_addr: f.remote.to_string(),
        host: f.host.clone(),
        host_source: f.host_source,
        iface: names.get(f.key.ifindex),
        state: f.state,
        tx_rate: f.tx_rate,
        rx_rate: f.rx_rate,
        total: f.total.tx_bytes + f.total.rx_bytes,
        conn: f.conn,
    }
}

/// Human-readable byte count, e.g. "1.5M".
pub fn human(bytes: f64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = bytes;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{v:.0}{}", UNITS[u]) } else { format!("{v:.1}{}", UNITS[u]) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procmap::{RawSock, SocketTable};
    use netmon_common::{FlowKey, FlowStats};

    fn collector() -> Collector {
        let mut c = Collector::new(30);
        let mk = |port: u16, tx: u64| {
            let mut k = FlowKey { family: 4, proto: IPPROTO_TCP, local_port: port, remote_port: 443, ifindex: 2, ..Default::default() };
            k.local_addr[..4].copy_from_slice(&[10, 0, 0, 2]);
            k.remote_addr[..4].copy_from_slice(&[1, 1, 1, 1]);
            (k, FlowStats { tx_bytes: tx, ..Default::default() })
        };
        c.ingest([mk(1, 0), mk(2, 0)], 1.0);
        c.ingest([mk(1, 100), mk(2, 5000)], 1.0);
        let table = SocketTable::build(
            vec![RawSock { proto: IPPROTO_TCP, local: "10.0.0.2:1".parse().unwrap(), remote: "1.1.1.1:443".parse().unwrap(), state: "ESTAB", inode: 9 }],
            &HashMap::from([(9, Owner::new(7, "curl"))]),
        );
        c.resolve(&table, &[], &crate::procmap::Listeners::default(), |_| None);
        c
    }

    #[test]
    fn sorts_by_rate_and_filters() {
        let c = collector();
        let mut app = App::default();
        let rows = app.conn_rows(&c, &Names::default());
        assert_eq!(rows[0].tx_rate, 5000.0);
        assert_eq!(rows[1].process, "curl");
        app.filter = "CURL".into();
        let rows = app.conn_rows(&c, &Names::default());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, "ESTAB");
    }

    #[test]
    fn groups_processes() {
        let rows = App::default().proc_rows(&collector(), &Names::default());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].process, "?");
    }

    #[test]
    fn filter_editing_consumes_keys() {
        let mut app = App::default();
        app.on_key(Key::Char('/'));
        app.on_key(Key::Char('q'));
        assert!(!app.quit);
        assert_eq!(app.filter, "q");
        app.on_key(Key::Enter);
        app.on_key(Key::Char('q'));
        assert!(app.quit);
    }

    #[test]
    fn arrows_switch_tabs_and_esc_does_not_quit() {
        let mut app = App::default();
        app.on_key(Key::Left);
        assert_eq!(app.tab, Tab::Rules, "wraps around");
        app.on_key(Key::Right);
        assert_eq!(app.tab, Tab::Connections);
        app.on_key(Key::Right);
        assert_eq!(app.tab, Tab::Processes);
        app.filter = "fire".into();
        app.on_key(Key::Esc);
        assert!(!app.quit);
        assert!(app.filter.is_empty());
        app.on_key(Key::Esc);
        assert!(!app.quit);
        // While typing a filter, arrows do not switch tabs.
        app.on_key(Key::Char('/'));
        app.on_key(Key::Right);
        assert_eq!(app.tab, Tab::Processes);
    }

    #[test]
    fn enter_starts_capture_and_capture_keys_map_to_actions() {
        let mut app = App::default();
        app.on_key(Key::Char('2'));
        assert_eq!(app.on_key(Key::Enter), Some(Action::StartCapture(Tab::Processes)));
        app.on_key(Key::Char('4'));
        assert_eq!(app.on_key(Key::Enter), None);
        assert_eq!(app.on_key(Key::Char('s')), Some(Action::SavePcap));
        assert_eq!(app.on_key(Key::Down), Some(Action::MovePacket(1)));
        // Outside the capture tab, 's' and 'x' do nothing.
        app.on_key(Key::Char('1'));
        assert_eq!(app.on_key(Key::Char('s')), None);
    }

    #[test]
    fn human_units() {
        assert_eq!(human(512.0), "512B");
        assert_eq!(human(1536.0), "1.5K");
        assert_eq!(human(3.0 * 1024.0 * 1024.0), "3.0M");
    }

    #[test]
    fn selection_follows_row_when_order_changes() {
        let ids = |ports: &[u32]| ports.iter().map(|p| RowId::Iface(*p)).collect::<Vec<_>>();
        let mut app = App::default();
        app.sync_selection(&ids(&[1, 2, 3]));
        app.on_key(Key::Down);
        assert_eq!(app.sync_selection(&ids(&[1, 2, 3])), 1);
        // Row 2 moves to the top: the cursor goes with it.
        assert_eq!(app.sync_selection(&ids(&[2, 3, 1])), 0);
        // A move applies relative to the anchored row, even after a re-sort.
        app.on_key(Key::Down);
        assert_eq!(app.selected_in(&ids(&[3, 1, 2])), Some(2));
        assert_eq!(app.sync_selection(&ids(&[3, 2, 1])), 2);
        // The row is gone: keep the index, clamped.
        assert_eq!(app.sync_selection(&ids(&[3, 2])), 1);
        app.on_key(Key::Home);
        assert_eq!(app.sync_selection(&ids(&[3, 2])), 0);
        assert_eq!(app.sync_selection(&[]), 0);
    }

    #[test]
    fn virtual_interface_rows_hidden_until_v() {
        let mut c = Collector::new(30);
        let k = |ifindex| FlowKey { family: 4, proto: 6, local_port: 1, remote_port: 443, ifindex, ..Default::default() };
        c.ingest([(k(2), FlowStats { tx_bytes: 5, ..Default::default() }), (k(18), FlowStats { tx_bytes: 5, ..Default::default() })], 1.0);
        let mut names = Names::default();
        names.update(&[
            crate::ifaces::Iface { index: 2, name: "enp5s0".into(), l3_offset: 14, kind: crate::ifaces::Kind::Physical },
            crate::ifaces::Iface { index: 18, name: "veth1".into(), l3_offset: 14, kind: crate::ifaces::Kind::Peer },
        ]);
        let mut app = App::default();
        assert_eq!(app.conn_rows(&c, &names).len(), 1);
        app.on_key(Key::Char('v'));
        assert_eq!(app.conn_rows(&c, &names).len(), 2);
        assert_eq!(names.physical(), std::collections::HashSet::from([2]));
    }

    #[test]
    fn container_owner_shows_the_container() {
        let mut c = Collector::new(30);
        let k = FlowKey { family: 4, proto: 6, local_port: 1, remote_port: 443, ifindex: 2, ..Default::default() };
        c.ingest([(k, FlowStats { tx_bytes: 5, ..Default::default() })], 1.0);
        c.flows.get_mut(&k).unwrap().owner = Some(Owner { container: Some("web".into()), ..Owner::new(7, "curl") });
        let rows = App::default().conn_rows(&c, &Names::default());
        assert_eq!((rows[0].process.as_str(), rows[0].pid.as_str()), ("container:web/curl", "7"));
    }

    #[test]
    fn answer_keys_only_while_asking() {
        let mut app = App::default();
        assert_eq!(app.on_key(Key::Char('a')), None);
        app.tab = Tab::Rules;
        assert_eq!(app.on_key(Key::Char('d')), Some(Action::RemoveRule));
        let p = crate::ask::Prompt {
            id: 1,
            pid: 1,
            comm: "x".into(),
            exe: String::new(),
            user: String::new(),
            dests: Vec::new(),
            since: std::time::Instant::now(),
            selected: 0,
            scope: crate::ask::Scope::Program,
        };
        app.ask = Some((p, 0));
        assert_eq!(app.on_key(Key::Char('a')), Some(Action::Answer(Answer::Rule { allow: true, always: false })));
        assert_eq!(app.on_key(Key::Char('D')), Some(Action::Answer(Answer::Rule { allow: false, always: true })));
        assert_eq!(app.on_key(Key::Char('d')), Some(Action::Answer(Answer::Rule { allow: false, always: false })), "d answers, not remove");
        assert_eq!(app.on_key(Key::Char('o')), Some(Action::Answer(Answer::Once { allow: true })));
        assert_eq!(app.on_key(Key::Right), Some(Action::AskScope(1)), "arrows steer the question, not the tabs");
        assert_eq!(app.on_key(Key::Down), Some(Action::AskSelect(1)));
        assert_eq!(app.on_key(Key::Char('5')), None, "other keys still work");
    }

    #[test]
    fn block_keys_only_where_they_apply() {
        let mut app = App::default();
        assert_eq!(app.on_key(Key::Char('b')), Some(Action::ToggleBlockRemote));
        assert_eq!(app.on_key(Key::Char('B')), Some(Action::ToggleBlockPort));
        assert_eq!(app.on_key(Key::Char('d')), None);
        app.on_key(Key::Char('5'));
        assert_eq!(app.tab, Tab::Rules);
        assert_eq!(app.on_key(Key::Char('d')), Some(Action::RemoveRule));
        assert_eq!(app.on_key(Key::Char('s')), Some(Action::SaveRules));
        assert_eq!(app.on_key(Key::Char('b')), None);
        assert_eq!(app.on_key(Key::Enter), None);
        app.on_key(Key::Right);
        assert_eq!(app.tab, Tab::Connections, "wraps");
    }
}

