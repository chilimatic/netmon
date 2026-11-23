//! Feeds the connection log: new connections from the flow table, denied
//! outbound connections from the kernel's deny events.

use super::*;
use crate::connlog::Entry;

/// Deny events read per tick at most.
const DENY_BATCH: usize = 4096;

impl<K: Kernel> Monitor<K> {
    /// Writes the new connections and the denials since the last tick.
    /// Returns an error message the first time writing fails.
    pub(crate) fn log_connections(&mut self, now: Instant) -> Option<String> {
        let mut denies = Vec::new();
        self.probe.drain_denies(DENY_BATCH, |e| denies.push(*e));
        self.conn_log.as_ref()?;
        let time = crate::rulefile::utc(rules::unix_now());
        let mut entries = Vec::new();
        for ev in &denies {
            let remote = ask::remote(&ev.key);
            let (mut comm, exe) = self.process_of(ev.tgid);
            if comm.is_empty() {
                let end = ev.comm.iter().position(|b| *b == 0).unwrap_or(ev.comm.len());
                comm = text::sanitize(&String::from_utf8_lossy(&ev.comm[..end]));
            }
            entries.push((
                true,
                Entry {
                    time: time.clone(),
                    event: "denied".into(),
                    dir: "out".into(),
                    proto: rules::proto_name(ev.key.proto).into(),
                    remote,
                    port: ev.key.remote_port,
                    host: self.hosts.get(remote, now).unwrap_or_default().to_string(),
                    pid: ev.tgid,
                    comm,
                    exe,
                },
            ));
        }
        // A flow is logged once its owner is known, or on its second tick
        // without one.
        let mut pending = HashSet::new();
        for (k, f) in &self.collector.flows {
            if self.log_done.contains(k) || !matches!(k.proto, netmon_common::IPPROTO_TCP | netmon_common::IPPROTO_UDP) {
                continue;
            }
            if f.owner.is_none() && !self.log_pending.contains(k) {
                pending.insert(*k);
                continue;
            }
            let (pid, comm, exe) = match &f.owner {
                Some(o) => {
                    let d = o.details.as_ref();
                    let name = d.map(|d| d.name.as_str()).filter(|n| !n.is_empty()).unwrap_or(&o.comm);
                    let comm = match &o.container {
                        Some(c) => format!("container:{c}/{name}"),
                        None => name.to_string(),
                    };
                    (o.pid, comm, d.map(|d| d.exe.clone()).unwrap_or_default())
                }
                None => (0, String::new(), String::new()),
            };
            let dir = match f.conn.map(|c| c.dir) {
                Some(netmon_common::DIR_OUT) => "out",
                Some(netmon_common::DIR_IN) => "in",
                _ => "",
            };
            let remote = crate::collector::addr(k.family, &k.remote_addr, k.remote_port);
            entries.push((
                false,
                Entry {
                    time: time.clone(),
                    event: "new".into(),
                    dir: dir.into(),
                    proto: rules::proto_name(k.proto).into(),
                    remote: remote.ip(),
                    port: remote.port(),
                    host: f.host.clone().unwrap_or_default(),
                    pid,
                    comm,
                    exe,
                },
            ));
            self.log_done.insert(*k);
        }
        self.log_pending = pending;
        let flows = &self.collector.flows;
        self.log_done.retain(|k| flows.contains_key(k));
        let log = self.conn_log.as_mut()?;
        let mut error = None;
        for (denied, e) in entries {
            let r = if denied { log.denied(&e, now) } else { log.new_conn(&e) };
            error = error.or(r);
        }
        error
    }

    /// Process name and exe of `pid`, empty if unknown or gone.
    fn process_of(&mut self, pid: u32) -> (String, String) {
        if pid == 0 {
            return (String::new(), String::new());
        }
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).map(|c| text::sanitize(c.trim())).unwrap_or_default();
        let mut owner = Owner::new(pid, &comm);
        self.procs.fill(&mut owner, read_details);
        (comm, owner.details.map(|d| d.exe).unwrap_or_default())
    }
}
