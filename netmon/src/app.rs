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
    Graph,
    Hosts,
    Log,
    Usage,
    Devices,
}

impl Tab {
    pub const ALL: [Tab; 10] = [
        Tab::Connections,
        Tab::Processes,
        Tab::Interfaces,
        Tab::Capture,
        Tab::Rules,
        Tab::Graph,
        Tab::Hosts,
        Tab::Log,
        Tab::Usage,
        Tab::Devices,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Connections => "Connections",
            Tab::Processes => "Processes",
            Tab::Interfaces => "Interfaces",
            Tab::Capture => "Capture",
            Tab::Rules => "Rules",
            Tab::Graph => "Graph",
            Tab::Hosts => "Hosts",
            Tab::Log => "Log",
            Tab::Usage => "Usage",
            Tab::Devices => "Devices",
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

/// The column titles of the Usage tab. The `s` key steps through them to pick the sort column.
pub const USAGE_COLUMNS: [&str; 6] = ["Program", "Today ↓", "Today ↑", "Yesterday", "7 days", "30 days"];

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
    Host(u32),
    /// A line of the connection log, by its content.
    Log(u64),
    /// A program in the Usage tab.
    Usage(String),
    /// A device by its MAC address.
    Device([u8; 6]),
    /// A DNS log entry, by its content.
    Dns(u64),
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
    /// Country and network owner of the remote address, if known.
    pub geo: String,
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
    /// The Usage column that sorts the rows (index into `USAGE_COLUMNS`), and whether the order is reversed.
    pub usage_sort: usize,
    pub usage_reverse: bool,
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
    /// main loop; while set and not hidden, a and d answer it.
    pub ask: Option<(crate::ask::Prompt, usize)>,
    /// The questions are put aside (Esc): the tab gets its keys back, the
    /// header counts the questions, ? shows them again.
    pub ask_hidden: bool,
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
    /// Seconds of animation in the Graph tab. Stands still while paused.
    pub anim: f64,
    /// Labels of the graph nodes as last drawn, for Enter.
    pub graph_labels: Vec<String>,
    /// Selected graph node.
    pub graph_sel: usize,
    /// Block targets of the graph nodes as last drawn, for b.
    pub graph_targets: Vec<crate::graph::Target>,
    /// What the graph rings show (z).
    pub graph_level: crate::graph::Level,
    /// Dot motion per edge (process label, remote label).
    pub graph_motion: HashMap<(String, String), crate::graph::Motion>,
    /// `anim` at the last graph frame.
    pub anim_drawn: f64,
    /// Typing a hostname to block (Hosts tab, a).
    pub editing_host: bool,
    pub host_input: String,
    /// The "follow stream" view, while open.
    pub stream: Option<StreamView>,
    /// Typing the display filter of the capture (Capture tab, /).
    pub editing_capture_filter: bool,
    pub capture_filter_input: String,
    /// The newest lines of the connection log, newest first (Log tab).
    pub log: Vec<crate::connlog::Entry>,
    /// Why the log could not be read, empty if it could.
    pub log_error: String,
    /// Country and AS lookups (DB-IP Lite), if the files exist.
    pub geo: crate::geo::Geo,
    /// Traffic per program (Usage tab), and why the file could not be read.
    pub usage: Vec<crate::usage::UsageRow>,
    pub usage_error: String,
    /// Devices on the LANs (Devices tab), from the monitor.
    pub devices: Vec<crate::devices::Device>,
    /// The DNS log, oldest first, and whether the Log tab shows it.
    pub dns: std::collections::VecDeque<crate::dnslog::DnsEntry>,
    pub show_dns: bool,
    /// The profile picker is open (Rules tab, P): names and selection.
    pub picking_profile: bool,
    /// Learning mode (Rules tab, G): suggested allow rules and selection.
    pub suggestions: Vec<crate::learn::Suggestion>,
    pub suggest_sel: usize,
    pub picking_suggestions: bool,
    /// The connection log, for the Log tab and the suggestions.
    pub log_path: std::path::PathBuf,
    pub profiles: Vec<String>,
    pub profile_sel: usize,
}

impl Default for App {
    fn default() -> Self {
        App {
            tab: Tab::Connections,
            sort: Sort::Rate,
            usage_sort: 1,
            usage_reverse: false,
            filter: String::new(),
            editing_filter: false,
            paused: false,
            show_graph: true,
            show_hosts: true,
            show_virtual: false,
            ask: None,
            ask_hidden: false,
            interval_secs: 1.0,
            selected: 0,
            anchor: None,
            pending: 0,
            quit: false,
            status: String::new(),
            anim: 0.0,
            graph_labels: Vec::new(),
            graph_sel: 0,
            graph_targets: Vec::new(),
            graph_level: crate::graph::Level::default(),
            graph_motion: HashMap::new(),
            anim_drawn: 0.0,
            editing_host: false,
            host_input: String::new(),
            stream: None,
            editing_capture_filter: false,
            capture_filter_input: String::new(),
            log: Vec::new(),
            log_error: String::new(),
            geo: crate::geo::Geo::default(),
            usage: Vec::new(),
            usage_error: String::new(),
            devices: Vec::new(),
            dns: Default::default(),
            show_dns: false,
            picking_profile: false,
            suggestions: Vec::new(),
            suggest_sel: 0,
            picking_suggestions: false,
            log_path: crate::connlog::DEFAULT_PATH.into(),
            profiles: Vec::new(),
            profile_sel: 0,
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

/// The open "follow stream" view (Capture tab, S).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StreamView {
    pub title: String,
    /// One entry per text line: Some(true) client, Some(false) server,
    /// None a note (missing bytes).
    pub lines: Vec<(Option<bool>, String)>,
    /// First shown line.
    pub scroll: usize,
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
    /// Block (or unblock) QUIC of the exe of the selected process.
    ToggleQuicProcess,
    /// Remove the selected rule in the Rules tab.
    RemoveRule,
    /// Step the end time of the selected rule: 1 hour, 1 day, never.
    CycleRuleTimer,
    /// Block a hostname pattern typed in the Hosts tab.
    BlockHost(String),
    /// Block the hostname of the selected connection.
    BlockHostOfRow,
    /// Remove the selected host block or list in the Hosts tab.
    RemoveHost,
    /// Read the host block lists again.
    ReloadBlocklists,
    /// ARP requests to every address of the LANs now.
    ScanDevices,
    /// Block the name of the selected DNS log entry.
    BlockDnsName,
    /// Next bandwidth limit of the selected process's exe (off, 1, 5, 20 MB/s).
    CycleLimit,
    /// Suggest allow rules from the connection log (the client opens the list).
    SuggestRules,
    /// Add the picked suggestions.
    AddSuggested,
    /// Open the profile picker (the client lists the profiles).
    PickProfile,
    /// Set the display filter of the capture; empty clears it.
    SetCaptureFilter(String),
    /// Show the TCP stream of the selected packet.
    FollowStream,
    /// Switch to this rule profile.
    LoadProfile(String),
    /// Block what the selected graph node stands for.
    BlockGraphNode,
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
    /// otherwise it ends when the monitor stops.
    Rule { allow: bool, always: bool },
    /// A rule for the chosen scope that ends after `secs`.
    Timed { allow: bool, secs: u64 },
}

/// The end time of a timed answer (`h`, `H`).
pub const ANSWER_SECS: u64 = 3600;

impl App {
    pub fn on_key(&mut self, key: Key) -> Option<Action> {
        if let Some(v) = self.stream.as_mut() {
            let last = v.lines.len().saturating_sub(1);
            match key {
                Key::Up | Key::Char('k') => v.scroll = v.scroll.saturating_sub(1),
                Key::Down | Key::Char('j') => v.scroll = (v.scroll + 1).min(last),
                Key::PageUp => v.scroll = v.scroll.saturating_sub(20),
                Key::PageDown => v.scroll = (v.scroll + 20).min(last),
                Key::Home => v.scroll = 0,
                Key::End => v.scroll = last,
                Key::Esc | Key::Char('q') | Key::Char('S') => self.stream = None,
                _ => {}
            }
            return None;
        }
        if self.picking_suggestions {
            let n = self.suggestions.len();
            match key {
                Key::Up | Key::Char('k') => self.suggest_sel = self.suggest_sel.saturating_sub(1),
                Key::Down | Key::Char('j') => self.suggest_sel = (self.suggest_sel + 1).min(n.saturating_sub(1)),
                Key::PageUp => self.suggest_sel = self.suggest_sel.saturating_sub(20),
                Key::PageDown => self.suggest_sel = (self.suggest_sel + 20).min(n.saturating_sub(1)),
                Key::Char(' ') => {
                    if let Some(s) = self.suggestions.get_mut(self.suggest_sel) {
                        s.picked = !s.picked;
                    }
                }
                Key::Char('a') => {
                    let all = self.suggestions.iter().all(|s| s.picked);
                    self.suggestions.iter_mut().for_each(|s| s.picked = !all);
                }
                Key::Enter => {
                    self.picking_suggestions = false;
                    return Some(Action::AddSuggested);
                }
                Key::Esc | Key::Char('q') => self.picking_suggestions = false,
                _ => {}
            }
            return None;
        }
        if self.picking_profile {
            match key {
                Key::Up | Key::Char('k') => self.profile_sel = self.profile_sel.saturating_sub(1),
                Key::Down | Key::Char('j') => {
                    self.profile_sel = (self.profile_sel + 1).min(self.profiles.len().saturating_sub(1));
                }
                Key::Enter => {
                    self.picking_profile = false;
                    return self.profiles.get(self.profile_sel).cloned().map(Action::LoadProfile);
                }
                Key::Esc | Key::Char('q') => self.picking_profile = false,
                _ => {}
            }
            return None;
        }
        if self.editing_capture_filter {
            match key {
                Key::Char(c) => self.capture_filter_input.push(c),
                Key::Backspace => {
                    self.capture_filter_input.pop();
                }
                Key::Enter => {
                    self.editing_capture_filter = false;
                    return Some(Action::SetCaptureFilter(self.capture_filter_input.trim().to_string()));
                }
                Key::Esc => self.editing_capture_filter = false,
                _ => {}
            }
            return None;
        }
        if self.editing_host {
            match key {
                Key::Char(c) => self.host_input.push(c),
                Key::Backspace => {
                    self.host_input.pop();
                }
                Key::Enter => {
                    self.editing_host = false;
                    let p = std::mem::take(&mut self.host_input);
                    return (!p.trim().is_empty()).then_some(Action::BlockHost(p));
                }
                Key::Esc => {
                    self.host_input.clear();
                    self.editing_host = false;
                }
                _ => {}
            }
            return None;
        }
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
        if self.ask.is_some() && self.ask_hidden && matches!(key, Key::Char('?')) {
            self.ask_hidden = false;
            return None;
        }
        if self.ask.is_some() && !self.ask_hidden {
            let rule = |allow, always| Some(Action::Answer(Answer::Rule { allow, always }));
            match key {
                Key::Esc => {
                    self.ask_hidden = true;
                    return None;
                }
                Key::Char('a') => return rule(true, false),
                Key::Char('A') => return rule(true, true),
                Key::Char('d') => return rule(false, false),
                Key::Char('D') => return rule(false, true),
                Key::Char('h') => return Some(Action::Answer(Answer::Timed { allow: true, secs: ANSWER_SECS })),
                Key::Char('H') => return Some(Action::Answer(Answer::Timed { allow: false, secs: ANSWER_SECS })),
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
                Key::Char('S') => return Some(Action::FollowStream),
                // The input keeps the last filter, to edit it.
                Key::Char('/') => {
                    self.editing_capture_filter = true;
                    return None;
                }
                _ => {}
            }
        }
        if self.tab == Tab::Graph {
            let n = self.graph_labels.len().max(1);
            match key {
                Key::Up | Key::Char('k') => {
                    self.graph_sel = (self.graph_sel + n - 1) % n;
                    return None;
                }
                Key::Down | Key::Char('j') => {
                    self.graph_sel = (self.graph_sel + 1) % n;
                    return None;
                }
                Key::Char('z') => {
                    self.graph_level = self.graph_level.next();
                    self.graph_sel = 0;
                    self.graph_motion.clear();
                    return None;
                }
                Key::Char('b') => return Some(Action::BlockGraphNode),
                // The Connections tab, filtered to the selected node.
                Key::Enter => {
                    if let Some(l) = self.graph_labels.get(self.graph_sel).filter(|_| self.graph_sel > 0) {
                        self.filter = l.clone();
                        self.set_tab(Tab::Connections);
                    }
                    return None;
                }
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
            Key::Char('6') => self.set_tab(Tab::Graph),
            Key::Char('7') => self.set_tab(Tab::Hosts),
            Key::Char('8') => self.set_tab(Tab::Log),
            Key::Char('9') => self.set_tab(Tab::Usage),
            Key::Char('0') => self.set_tab(Tab::Devices),
            Key::Char('a') if self.tab == Tab::Hosts => self.editing_host = true,
            Key::Char('d') if self.tab == Tab::Hosts => return Some(Action::RemoveHost),
            Key::Char('r') if self.tab == Tab::Hosts => return Some(Action::ReloadBlocklists),
            Key::Char('r') if self.tab == Tab::Devices => return Some(Action::ScanDevices),
            Key::Char('d') if self.tab == Tab::Log => {
                self.show_dns = !self.show_dns;
                self.reset_selection();
            }
            Key::Char('b') if self.tab == Tab::Log && self.show_dns => return Some(Action::BlockDnsName),
            Key::Char('s') if self.tab == Tab::Hosts => return Some(Action::SaveRules),
            Key::Char('H') if self.tab == Tab::Connections => return Some(Action::BlockHostOfRow),
            Key::Char('b') if self.tab == Tab::Connections => return Some(Action::ToggleBlockRemote),
            Key::Char('B') if self.tab == Tab::Connections => return Some(Action::ToggleBlockPort),
            Key::Char('b') if self.tab == Tab::Processes => return Some(Action::ToggleBlockProcess),
            Key::Char('Q') if self.tab == Tab::Processes => return Some(Action::ToggleQuicProcess),
            Key::Char('L') if self.tab == Tab::Processes => return Some(Action::CycleLimit),
            Key::Char('d') if self.tab == Tab::Rules => return Some(Action::RemoveRule),
            Key::Char('t') if self.tab == Tab::Rules => return Some(Action::CycleRuleTimer),
            Key::Char('P') if self.tab == Tab::Rules => return Some(Action::PickProfile),
            Key::Char('G') if self.tab == Tab::Rules => return Some(Action::SuggestRules),
            Key::Char('s') if self.tab == Tab::Rules => return Some(Action::SaveRules),
            Key::Char('s') if self.tab == Tab::Usage => {
                self.usage_sort = (self.usage_sort + 1) % USAGE_COLUMNS.len();
                self.usage_reverse = false;
            }
            Key::Char('S') if self.tab == Tab::Usage => self.usage_reverse = !self.usage_reverse,
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

    /// Adds new DNS log entries; the oldest go first.
    pub fn add_dns(&mut self, entries: Vec<crate::dnslog::DnsEntry>) {
        for e in entries {
            if self.dns.len() >= crate::dnslog::MAX_ENTRIES {
                self.dns.pop_front();
            }
            self.dns.push_back(e);
        }
    }

    /// The DNS log entries that match the filter, newest first, with their ids.
    pub fn dns_rows(&self) -> Vec<(&crate::dnslog::DnsEntry, RowId)> {
        use std::hash::{Hash, Hasher};
        self.dns
            .iter()
            .rev()
            .filter(|e| {
                let (server, pid) = (e.server.to_string(), e.pid.map(|p| p.to_string()).unwrap_or_default());
                let blocked = if e.blocked { "blocked" } else { "" };
                self.matches(&[&e.program, &pid, &server, &e.name, &e.qtype, &e.rcode, &e.answers.join(" "), blocked])
            })
            .map(|e| {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                e.hash(&mut h);
                (e, RowId::Dns(h.finish()))
            })
            .collect()
    }

    /// The log lines that match the filter, newest first, with their ids.
    pub fn log_rows(&self) -> Vec<(&crate::connlog::Entry, RowId)> {
        use std::hash::{Hash, Hasher};
        self.log
            .iter()
            .filter(|e| {
                let (remote, port, pid) = (e.remote.to_string(), e.port.to_string(), e.pid.to_string());
                self.matches(&[&e.event, &e.dir, &e.proto, &remote, &port, &e.host, &pid, &e.comm, &e.exe, &e.time])
            })
            .map(|e| {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                e.hash(&mut h);
                (e, RowId::Log(h.finish()))
            })
            .collect()
    }

    /// The devices that match the filter, in the monitor's order (by
    /// interface and address).
    pub fn device_rows(&self) -> Vec<&crate::devices::Device> {
        self.devices
            .iter()
            .filter(|d| self.matches(&[&d.ip.to_string(), &crate::devices::mac_text(&d.mac), &d.vendor, &d.name, &d.iface]))
            .collect()
    }

    /// The Usage rows that match the filter, sorted by the chosen column.
    /// Programs sort A to Z, byte counts largest first. `usage_reverse` flips the order.
    pub fn usage_rows(&self) -> Vec<&crate::usage::UsageRow> {
        let mut rows: Vec<&crate::usage::UsageRow> = self.usage.iter().filter(|r| self.matches(&[&r.program])).collect();
        let sum = |w: [u64; 2]| w[0] + w[1];
        let key = |r: &crate::usage::UsageRow| match self.usage_sort {
            1 => r.today[1],
            2 => r.today[0],
            3 => sum(r.yesterday),
            4 => sum(r.week),
            _ => sum(r.month),
        };
        if self.usage_sort == 0 {
            rows.sort_by(|a, b| a.program.cmp(&b.program));
        } else {
            rows.sort_by(|a, b| key(b).cmp(&key(a)).then(a.program.cmp(&b.program)));
        }
        if self.usage_reverse {
            rows.reverse();
        }
        rows
    }

    pub fn conn_rows(&self, c: &Collector, names: &Names) -> Vec<ConnRow> {
        let mut rows: Vec<ConnRow> = c
            .flows
            .values()
            .filter(|f| self.show_virtual || !names.kind(f.key.ifindex).is_virtual())
            .map(|f| {
                let mut r = conn_row(f, names, self.show_hosts);
                r.geo = self.geo.label(crate::procmap::normalize(crate::collector::addr(f.key.family, &f.key.remote_addr, 0)).ip());
                r
            })
            .filter(|r| {
                let host = r.host.as_deref().unwrap_or("");
                self.matches(&[&r.process, &r.pid, &r.exe, &r.user, &r.unit, &r.local, &r.remote, host, &r.iface, r.proto, &r.geo])
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

pub(crate) fn owner_cols(f: &Flow) -> (String, String) {
    match &f.owner {
        Some(Owner { container: Some(c), comm, pid, .. }) => (format!("container:{c}/{comm}"), pid.to_string()),
        Some(o) => (o.comm.clone(), o.pid.to_string()),
        None => (no_owner(f).into(), "-".into()),
    }
}

/// Why a flow has no process, as far as its counters tell:
/// - "(icmp)", "(ip)": not TCP or UDP, which have no socket to map.
/// - "(closed)": the socket closed (TIME-WAIT and the like), or the host
///   sent from a socket whose process is gone.
/// - "(inbound, no socket)": only received, nothing sent back: scans,
///   packets to closed ports, broadcasts.
/// - "(forwarded)": sent without a socket of this host. Container or VM
///   traffic after NAT, before netmon read the container's tables, or a
///   kernel socket (WireGuard, NFS).
pub(crate) fn no_owner(f: &Flow) -> &'static str {
    const CLOSED: [&str; 6] = ["TIME-WAIT", "CLOSE", "CLOSE-WAIT", "LAST-ACK", "CLOSING", "FIN-WAIT-2"];
    match f.key.proto {
        1 | 58 => "(icmp)",
        IPPROTO_TCP | IPPROTO_UDP => {
            if CLOSED.contains(&f.state) || f.total.cookie != 0 {
                "(closed)"
            } else if f.total.tx_bytes == 0 {
                "(inbound, no socket)"
            } else {
                "(forwarded)"
            }
        }
        _ => "(ip)",
    }
}

static NO_DETAILS: ProcDetails =
    ProcDetails { name: String::new(), exe: String::new(), user: String::new(), unit: String::new(), cgroup: String::new() };

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
        geo: String::new(),
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
        assert_eq!(rows[0].process, "(forwarded)", "sent, no socket");
    }

    #[test]
    fn flows_without_owner_say_why() {
        let mut c = collector();
        let f = c.flows.values_mut().find(|f| f.owner.is_none()).unwrap();
        f.owner = None;
        assert_eq!(no_owner(f), "(forwarded)");
        f.total.cookie = 7;
        assert_eq!(no_owner(f), "(closed)", "a socket of a process that is gone");
        f.total.cookie = 0;
        f.total.tx_bytes = 0;
        assert_eq!(no_owner(f), "(inbound, no socket)");
        f.state = "TIME-WAIT";
        assert_eq!(no_owner(f), "(closed)");
        f.key.proto = 1;
        assert_eq!(no_owner(f), "(icmp)");
        f.key.proto = 47;
        assert_eq!(no_owner(f), "(ip)");
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
        assert_eq!(app.tab, Tab::Devices, "wraps around");
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
        assert_eq!(app.on_key(Key::Char('Q')), Some(Action::ToggleQuicProcess));
        app.on_key(Key::Char('4'));
        assert_eq!(app.on_key(Key::Enter), None);
        assert_eq!(app.on_key(Key::Char('s')), Some(Action::SavePcap));
        assert_eq!(app.on_key(Key::Down), Some(Action::MovePacket(1)));
        assert_eq!(app.on_key(Key::Char('/')), None);
        for c in "dns".chars() {
            assert_eq!(app.on_key(Key::Char(c)), None, "typing, not keys");
        }
        assert_eq!(app.on_key(Key::Enter), Some(Action::SetCaptureFilter("dns".into())));
        assert_eq!(app.on_key(Key::Char('S')), Some(Action::FollowStream));
        app.stream = Some(StreamView { lines: vec![(None, "a".into()), (None, "b".into())], ..StreamView::default() });
        assert_eq!(app.on_key(Key::Char('x')), None, "the view takes the keys");
        app.on_key(Key::End);
        assert_eq!(app.stream.as_ref().unwrap().scroll, 1);
        app.on_key(Key::Down);
        assert_eq!(app.stream.as_ref().unwrap().scroll, 1, "stops at the last line");
        app.on_key(Key::Esc);
        assert!(app.stream.is_none());
        assert_eq!(app.filter, "", "the table filter stays");
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
        assert_eq!(app.on_key(Key::Char('t')), Some(Action::CycleRuleTimer));
        assert_eq!(app.on_key(Key::Char('P')), Some(Action::PickProfile));
        app.profiles = vec!["default".into(), "home".into()];
        app.picking_profile = true;
        assert_eq!(app.on_key(Key::Char('d')), None, "the picker takes the keys");
        assert_eq!(app.on_key(Key::Down), None);
        assert_eq!(app.on_key(Key::Down), None, "stops at the end");
        assert_eq!(app.on_key(Key::Enter), Some(Action::LoadProfile("home".into())));
        assert!(!app.picking_profile);
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
        assert_eq!(app.on_key(Key::Char('H')), Some(Action::Answer(Answer::Timed { allow: false, secs: ANSWER_SECS })));
        assert_eq!(app.on_key(Key::Right), Some(Action::AskScope(1)), "arrows steer the question, not the tabs");
        assert_eq!(app.on_key(Key::Down), Some(Action::AskSelect(1)));
        assert_eq!(app.on_key(Key::Char('5')), None, "other keys still work");
        // Esc puts the questions aside: the tab gets d back.
        assert_eq!(app.on_key(Key::Esc), None);
        assert!(app.ask_hidden && !app.quit);
        assert_eq!(app.on_key(Key::Char('d')), Some(Action::RemoveRule));
        assert_eq!(app.on_key(Key::Char('?')), None);
        assert!(!app.ask_hidden);
        assert_eq!(app.on_key(Key::Char('d')), Some(Action::Answer(Answer::Rule { allow: false, always: false })));
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
        assert_eq!(app.tab, Tab::Graph);
        app.on_key(Key::Right);
        assert_eq!(app.tab, Tab::Hosts);
        assert_eq!(app.on_key(Key::Char('d')), Some(Action::RemoveHost));
        assert_eq!(app.on_key(Key::Char('r')), Some(Action::ReloadBlocklists));
        assert_eq!(app.on_key(Key::Char('a')), None);
        for c in "*.ads.example".chars() {
            assert_eq!(app.on_key(Key::Char(c)), None, "typing, not keys");
        }
        assert_eq!(app.on_key(Key::Enter), Some(Action::BlockHost("*.ads.example".into())));
        assert!(!app.editing_host && app.host_input.is_empty());
        app.on_key(Key::Right);
        assert_eq!(app.tab, Tab::Log);
        app.on_key(Key::Right);
        assert_eq!(app.tab, Tab::Usage);
        app.on_key(Key::Right);
        assert_eq!(app.tab, Tab::Devices);
        assert_eq!(app.on_key(Key::Char('r')), Some(Action::ScanDevices));
        app.on_key(Key::Right);
        assert_eq!(app.tab, Tab::Connections, "wraps");
        app.on_key(Key::Char('0'));
        assert_eq!(app.tab, Tab::Devices);
        app.on_key(Key::Char('1'));
        assert_eq!(app.on_key(Key::Char('H')), Some(Action::BlockHostOfRow));
    }

    #[test]
    fn graph_keys_select_nodes_and_enter_filters_connections() {
        let mut app = App::default();
        app.on_key(Key::Char('6'));
        assert_eq!(app.tab, Tab::Graph);
        app.graph_labels = vec!["this host".into(), "firefox".into(), "example.com".into()];
        app.on_key(Key::Enter);
        assert_eq!(app.tab, Tab::Graph, "the host node filters nothing");
        app.on_key(Key::Down);
        app.on_key(Key::Down);
        app.on_key(Key::Down);
        assert_eq!(app.graph_sel, 0, "wraps");
        app.on_key(Key::Up);
        assert_eq!(app.graph_sel, 2);
        app.on_key(Key::Enter);
        assert_eq!((app.tab, app.filter.as_str()), (Tab::Connections, "example.com"));
    }
}

