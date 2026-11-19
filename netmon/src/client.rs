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
            Action::ToggleBlockProcess => {
                let rows = app.proc_rows(&self.snap.collector, &self.snap.names);
                let ids: Vec<_> = rows.iter().map(|r| r.id()).collect();
                match app.selected_in(&ids).map(|i| &rows[i]) {
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
            Action::SaveRules => Ok(Request::SaveRules),
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
            Tab::Capture | Tab::Rules => Err("select a row in another tab".into()),
        }
    }
}

fn dest_id(d: &crate::ask::Dest) -> DestId {
    DestId::from(d)
}
