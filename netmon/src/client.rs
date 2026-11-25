//! The UI side of the monitor: the latest snapshot, the capture's decoded
//! packets, and the step from a key action on the selected row to a
//! request. Needs no privileges.

use crate::{
    app::{Action, App, Tab},
    capture::{self, Capture, Captured, Target},
    collector,
    proto::{DestId, RawPacket, Request, Snapshot},
    rules::BlockTarget,
};

pub struct Client {
    pub snap: Snapshot,
    /// The capture shown in the Capture tab, with its packets.
    pub capture: Option<Capture>,
    /// Id of `capture` at the monitor.
    capture_id: u64,
    /// Newest traffic data that arrived while paused.
    live: Option<collector::Collector>,
}

impl Client {
    pub fn new(snap: Snapshot, app: &mut App) -> Self {
        let mut c = Client { snap: snap.clone(), capture: None, capture_id: 0, live: None };
        c.apply(snap, app);
        c
    }

    /// Takes a new snapshot. While paused the traffic stays as it was;
    /// rules, questions and the capture state still follow the monitor.
    pub fn apply(&mut self, mut snap: Snapshot, app: &mut App) {
        if app.paused {
            std::mem::swap(&mut snap.collector, &mut self.snap.collector);
            self.live = Some(std::mem::replace(&mut self.snap.collector, collector::Collector::new(1)));
        } else {
            self.live = None;
        }
        if let Some(info) = &snap.capture {
            if info.id != self.capture_id || self.capture.is_none() {
                self.capture = Some(Capture::new(info.target.clone()));
                self.capture_id = info.id;
            }
            if let Some(cap) = self.capture.as_mut() {
                cap.running = info.running;
                cap.dropped = info.dropped;
            }
        }
        // The shown question keeps the destination and scope picked here.
        let picked = app.ask.as_ref().map(|(p, _)| (p.id, p.selected_dest().map(dest_id), p.scope));
        app.ask = snap.questions.first().map(|q| {
            let mut q = q.clone();
            if let Some((id, dest, scope)) = picked
                && id == q.id
            {
                q.scope = scope;
                if let Some(i) = dest.and_then(|d| q.dests.iter().position(|x| dest_id(x) == d)) {
                    q.selected = i;
                }
            }
            (q, snap.questions.len() - 1)
        });
        app.devices = snap.devices.clone();
        self.snap = snap;
    }

    /// Shows the newest traffic data after a pause.
    pub fn resume(&mut self) {
        if let Some(c) = self.live.take() {
            self.snap.collector = c;
        }
    }

    /// Decodes packets of the current capture.
    pub fn add_packets(&mut self, packets: Vec<RawPacket>) {
        if let Some(cap) = self.capture.as_mut() {
            for p in packets {
                cap.push(Captured::from_raw(p));
            }
        }
    }

    /// Carries out what only concerns this UI. Returns the request for the
    /// monitor, if the action needs one; problems go to `app.status`.
    pub fn action(&mut self, app: &mut App, action: Action) -> Option<Request> {
        let req = match action {
            Action::StartCapture(tab) => self.target_for(app, tab).map(Request::StartCapture),
            Action::StopCapture => Ok(Request::StopCapture),
            Action::SavePcap => {
                app.status = match &self.capture {
                    Some(cap) if !cap.packets.is_empty() => {
                        let dir = std::env::current_dir().unwrap_or_else(|_| ".".into());
                        match capture::save(cap, &dir) {
                            Ok(path) => format!("saved {} packets to {}", cap.packets.len(), path.display()),
                            Err(e) => format!("save failed: {e}"),
                        }
                    }
                    _ => "nothing to save".into(),
                };
                return None;
            }
            Action::FollowStream => {
                let Some(cap) = self.capture.as_ref() else {
                    app.status = "no capture".into();
                    return None;
                };
                let Some(at) = cap.packets.get(cap.selected) else {
                    app.status = "no packet selected".into();
                    return None;
                };
                match crate::stream::follow(&cap.packets, at) {
                    Some(s) => app.stream = Some(stream_view(&s)),
                    None => app.status = "follow stream: the selected packet is not TCP".into(),
                }
                return None;
            }
            Action::SetCaptureFilter(text) => {
                let Some(cap) = self.capture.as_mut() else {
                    app.status = "no capture".into();
                    return None;
                };
                if text.is_empty() {
                    cap.set_filter(None);
                    app.status = "capture filter cleared".into();
                } else {
                    match crate::pfilter::Filter::parse(&text) {
                        Ok(f) => {
                            app.status = format!("capture filter: {}", f.text());
                            cap.set_filter(Some(f));
                        }
                        Err(e) => app.status = format!("capture filter: {e}"),
                    }
                }
                return None;
            }
            Action::ClearCapture => {
                if let Some(cap) = self.capture.as_mut() {
                    cap.clear();
                }
                return None;
            }
            Action::MovePacket(d) => {
                if let Some(cap) = self.capture.as_mut() {
                    cap.select(d);
                }
                return None;
            }
            Action::JumpPacket(newest) => {
                if let Some(cap) = self.capture.as_mut() {
                    cap.select(if newest { isize::MAX / 2 } else { isize::MIN / 2 });
                }
                return None;
            }
            Action::ToggleBlockRemote => self.selected_conn(app).map(|k| {
                let remote = collector::addr(k.family, &k.remote_addr, k.remote_port);
                Request::ToggleBlock(BlockTarget::host(remote.ip()))
            }),
            Action::ToggleBlockPort => self.selected_conn(app).and_then(|k| match k.remote_port {
                0 => Err("this connection has no port".into()),
                port => Ok(Request::ToggleBlock(BlockTarget::Port(k.proto, port))),
            }),
            Action::ToggleBlockProcess | Action::ToggleQuicProcess => {
                let rows = app.proc_rows(&self.snap.collector, &self.snap.names);
                let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
                let quic = action == Action::ToggleQuicProcess;
                match app.selected_in(&ids).map(|i| &rows[i]) {
                    Some(r) if !r.exe.is_empty() && quic => Ok(Request::ToggleBlock(BlockTarget::Quic(r.exe.clone()))),
                    Some(r) if !r.exe.is_empty() => Ok(Request::ToggleBlock(BlockTarget::Exe(r.exe.clone()))),
                    Some(_) => Err("exe unknown for this process: block its remote address instead".into()),
                    None => Err("no process selected".into()),
                }
            }
            Action::RemoveRule => {
                let rules = &self.snap.rules.rules;
                let ids: Vec<_> = rules.iter().map(|r| crate::app::RowId::Rule(r.id)).collect();
                app.selected_in(&ids).map(|i| Request::RemoveRule(rules[i].id)).ok_or_else(|| "no rule selected".into())
            }
            Action::CycleRuleTimer => {
                let rules = &self.snap.rules.rules;
                let ids: Vec<_> = rules.iter().map(|r| crate::app::RowId::Rule(r.id)).collect();
                match app.selected_in(&ids).map(|i| &rules[i]) {
                    Some(r) => Ok(Request::SetRuleTimer { id: r.id, secs: next_timer(r.until, crate::rules::unix_now()) }),
                    None => Err("no rule selected".into()),
                }
            }
            Action::SaveRules => Ok(Request::SaveRules),
            Action::BlockHost(pattern) => Ok(Request::BlockHost { pattern, comment: String::new() }),
            Action::BlockHostOfRow => {
                let rows = app.conn_rows(&self.snap.collector, &self.snap.names);
                let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
                match app.selected_in(&ids).map(|i| &rows[i]) {
                    Some(r) => match &r.host {
                        Some(h) => Ok(Request::BlockHost { pattern: h.clone(), comment: String::new() }),
                        None => Err("no hostname known for this connection: b blocks its address".into()),
                    },
                    None => Err("no connection selected".into()),
                }
            }
            Action::BlockGraphNode => match app.graph_targets.get(app.graph_sel) {
                Some(crate::graph::Target::Exe(e)) => Ok(Request::ToggleBlock(BlockTarget::Exe(e.clone()))),
                Some(crate::graph::Target::Host(h)) => Ok(Request::BlockHost { pattern: h.clone(), comment: String::new() }),
                Some(crate::graph::Target::Addr(ip)) => Ok(Request::ToggleBlock(BlockTarget::host(*ip))),
                _ => Err("nothing to block for this node: select a process or a remote end".into()),
            },
            Action::RemoveHost => {
                let ids = crate::ui::host_row_ids(&self.snap.rules);
                match app.selected_in(&ids).map(|i| &ids[i]) {
                    Some(crate::app::RowId::Host(id)) => Ok(Request::RemoveHost(*id)),
                    _ => Err("no host selected".into()),
                }
            }
            Action::ReloadBlocklists => Ok(Request::ReloadBlocklists),
            Action::ScanDevices => Ok(Request::ScanDevices),
            Action::PickProfile => {
                let dir = std::path::Path::new(crate::rulefile::DEFAULT_PATH).with_file_name(crate::monitor::PROFILES_DIR);
                app.profiles = list_profiles(&dir);
                let active = if self.snap.rules.profile.is_empty() { "default" } else { &self.snap.rules.profile };
                app.profile_sel = app.profiles.iter().position(|p| p == active).unwrap_or(0);
                app.picking_profile = true;
                return None;
            }
            Action::LoadProfile(name) => Ok(Request::LoadProfile(name)),
            Action::Answer(answer) => match &app.ask {
                Some((p, _)) => match p.selected_dest() {
                    Some(d) => Ok(Request::Answer { question: p.id, dest: dest_id(d), scope: p.scope, answer }),
                    None => return None,
                },
                None => return None,
            },
            Action::AskSelect(step) => {
                if let Some((p, _)) = app.ask.as_mut() {
                    p.move_selection(step);
                }
                return None;
            }
            Action::AskScope(step) => {
                if let Some((p, _)) = app.ask.as_mut() {
                    p.scope = p.scope.step(step);
                }
                return None;
            }
        };
        req.map_err(|e| app.status = e).ok()
    }

    /// Shows the monitor's reply to `req`.
    pub fn replied(&mut self, app: &mut App, req: &Request, msg: String) {
        app.status = match req {
            Request::StartCapture(_) if msg.is_empty() => {
                app.tab = Tab::Capture;
                msg
            }
            Request::StopCapture if msg.is_empty() => match &self.capture {
                Some(cap) => format!("capture stopped, {} packets kept", cap.packets.len()),
                None => msg,
            },
            _ => msg,
        };
    }

    /// The flow key of the selected row in Connections.
    fn selected_conn(&self, app: &App) -> Result<netmon_common::FlowKey, String> {
        let rows = app.conn_rows(&self.snap.collector, &self.snap.names);
        let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
        app.selected_in(&ids).map(|i| rows[i].key).ok_or_else(|| "no connection selected".into())
    }

    /// Turns the selected row of a tab into a capture target.
    fn target_for(&self, app: &App, tab: Tab) -> Result<Target, String> {
        // Rows as the user sees them, so a paused view picks the shown row.
        let (c, names) = (&self.snap.collector, &self.snap.names);
        match tab {
            Tab::Interfaces => {
                let rows = app.iface_rows(c, names);
                let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
                let r = app.selected_in(&ids).map(|i| &rows[i]).ok_or("no interface selected")?;
                Ok(Target::Interface { index: r.index, name: r.name.clone() })
            }
            Tab::Processes => {
                let rows = app.proc_rows(c, names);
                let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
                let r = app.selected_in(&ids).map(|i| &rows[i]).ok_or("no process selected")?;
                let pid = r.pid_num.ok_or("owner unknown: capture its connections instead")?;
                Ok(Target::Process { pid, comm: r.process.clone() })
            }
            Tab::Connections => {
                let rows = app.conn_rows(c, names);
                let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
                let r = app.selected_in(&ids).map(|i| &rows[i]).ok_or("no connection selected")?;
                Ok(Target::Connection {
                    key: r.key,
                    label: format!("{} {} → {} on {}", r.proto, r.local, r.remote, r.iface),
                })
            }
            Tab::Capture | Tab::Rules | Tab::Graph | Tab::Hosts | Tab::Log | Tab::Usage | Tab::Devices => Err("select a row in another tab".into()),
        }
    }
}

/// The lines of a followed stream, for the view.
pub(crate) fn stream_view(s: &crate::stream::Stream) -> crate::app::StreamView {
    use crate::stream::{Piece, looks_like_tls, text};
    let mut lines = Vec::new();
    if looks_like_tls(s) {
        lines.push((None, "TLS: the payload is encrypted; netmon cannot show it as text.".to_string()));
    }
    for p in &s.pieces {
        match p {
            Piece::Data { client, bytes } => {
                lines.extend(text(bytes).split('\n').map(|l| (Some(*client), l.to_string())));
            }
            Piece::Missing { client, bytes } => {
                let side = if *client { "client" } else { "server" };
                lines.push((None, format!("[{bytes} bytes from the {side} missing: not captured]")));
            }
        }
    }
    crate::app::StreamView {
        title: format!(
            " tcp stream {} (client, red, {} bytes) ↔ {} (server, blue, {} bytes) ",
            s.client, s.bytes.0, s.server, s.bytes.1
        ),
        lines,
        scroll: 0,
    }
}

/// "default" and the profiles in `dir` (`<name>.toml`), sorted.
pub(crate) fn list_profiles(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let stem = name.strip_suffix(".toml")?;
            crate::monitor::check_profile_name(stem).ok()?;
            (stem != "default").then(|| stem.to_string())
        })
        .collect();
    names.sort();
    names.insert(0, "default".into());
    names
}

/// The next end time for `t` in the Rules tab: none, then 1 hour, then 1
/// day, then none again.
pub(crate) fn next_timer(until: Option<u64>, now: u64) -> Option<u64> {
    const HOUR: u64 = 3600;
    const DAY: u64 = 86_400;
    match until.map(|u| u.saturating_sub(now)) {
        None => Some(HOUR),
        Some(left) if left <= HOUR => Some(DAY),
        Some(_) => None,
    }
}

#[cfg(test)]
#[test]
fn timer_steps_hour_day_never() {
    assert_eq!(next_timer(None, 1000), Some(3600));
    assert_eq!(next_timer(Some(1000 + 3600), 1000), Some(86_400));
    assert_eq!(next_timer(Some(1000 + 86_400), 1000), None);
}

fn dest_id(d: &crate::ask::Dest) -> DestId {
    DestId::from(d)
}
