//! The UI's connection to `netmond`.

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    time::Duration,
};

use anyhow::{Context as _, bail};

use crate::proto::{self, Request, Snapshot, ToClient, ToDaemon};

/// Longest wait for the daemon's hello and first snapshot.
const HANDSHAKE: Duration = Duration::from_secs(5);

pub(crate) struct Remote {
    stream: UnixStream,
    rx: Receiver<Result<ToClient, String>>,
}

/// What the daemon said on connect.
pub(crate) struct Welcome {
    pub(crate) interval: Duration,
    pub(crate) warnings: Vec<String>,
    pub(crate) snapshot: Snapshot,
}

impl Remote {
    pub(crate) fn connect(path: &Path) -> anyhow::Result<(Self, Welcome)> {
        let stream = UnixStream::connect(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
                "connect {}: permission denied; add your user to group netmon (then log in again), \
                 or run netmon --local as root",
                path.display()
            ),
            std::io::ErrorKind::ConnectionRefused => anyhow::anyhow!(
                "connect {}: netmond does not run (socket left from an earlier run); start netmond, \
                 or run netmon --local as root",
                path.display()
            ),
            _ => anyhow::Error::new(e).context(format!("connect {}", path.display())),
        })?;
        let mut remote = Remote { rx: reader(stream.try_clone()?), stream };
        remote.send_line(&ToDaemon::Hello { version: proto::VERSION })?;
        let (interval, warnings) = match remote.recv(HANDSHAKE)? {
            ToClient::Hello { version, interval_ms, warnings } if version == proto::VERSION => {
                (Duration::from_millis(interval_ms), warnings)
            }
            ToClient::Hello { version, .. } => {
                bail!("netmond speaks protocol {version}, this netmon {}: install matching versions", proto::VERSION)
            }
            ToClient::Error(e) => bail!("netmond: {e}"),
            _ => bail!("netmond: no hello"),
        };
        let snapshot = match remote.recv(HANDSHAKE)? {
            ToClient::Snapshot(s) => *s,
            ToClient::Error(e) => bail!("netmond: {e}"),
            _ => bail!("netmond: no snapshot after hello"),
        };
        Ok((remote, Welcome { interval, warnings, snapshot }))
    }

    pub(crate) fn send(&mut self, req: Request) -> anyhow::Result<()> {
        self.send_line(&ToDaemon::Request(req))
    }

    /// Messages that arrived so far. An error when the daemon is gone.
    pub(crate) fn poll(&mut self) -> anyhow::Result<Vec<ToClient>> {
        let mut out = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(Ok(m)) => out.push(m),
                Ok(Err(e)) => bail!(e),
                Err(TryRecvError::Empty) => return Ok(out),
                Err(TryRecvError::Disconnected) => bail!("netmond closed the connection"),
            }
        }
    }

    fn send_line(&mut self, msg: &ToDaemon) -> anyhow::Result<()> {
        self.stream.write_all(proto::line(msg).as_bytes()).context("send to netmond")
    }

    fn recv(&mut self, timeout: Duration) -> anyhow::Result<ToClient> {
        match self.rx.recv_timeout(timeout) {
            Ok(Ok(m)) => Ok(m),
            Ok(Err(e)) => bail!(e),
            Err(RecvTimeoutError::Timeout) => bail!("netmond does not answer"),
            Err(RecvTimeoutError::Disconnected) => bail!("netmond closed the connection"),
        }
    }
}

/// Reads the daemon's lines in a thread. The daemon runs as root and is
/// trusted; its lines are not limited in length (a snapshot can be MBs).
fn reader(stream: UnixStream) -> Receiver<Result<ToClient, String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut r = BufReader::new(stream);
        let mut buf = String::new();
        loop {
            buf.clear();
            let msg = match r.read_line(&mut buf) {
                Ok(0) => Err("netmond closed the connection".to_string()),
                Ok(_) => serde_json::from_str(&buf).map_err(|e| format!("bad line from netmond: {e}")),
                Err(e) => Err(format!("read from netmond: {e}")),
            };
            let end = msg.is_err();
            if tx.send(msg).is_err() || end {
                break;
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{collector::Collector, ifaces::Names, rules::Rules};
    use std::os::unix::net::UnixListener;

    fn empty() -> Snapshot {
        Snapshot { collector: Collector::new(1), names: Names::default(), rules: Rules::default(), questions: Vec::new(), capture: None, devices: Vec::new() }
    }

    /// A daemon that reads one line, then writes `lines`, then reads
    /// requests into the returned channel.
    fn fake_daemon(name: &str, lines: Vec<ToClient>) -> (std::path::PathBuf, mpsc::Receiver<String>) {
        let _fs = crate::test_fs_lock();
        let dir = std::env::temp_dir().join(format!("netmon-remote-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let l = UnixListener::bind(&path).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = &s;
            let mut buf = String::new();
            while r.read_line(&mut buf).unwrap_or(0) > 0 {
                if buf.contains("Hello") {
                    for m in &lines {
                        w.write_all(proto::line(m).as_bytes()).unwrap();
                    }
                }
                let _ = tx.send(std::mem::take(&mut buf));
            }
        });
        (path, rx)
    }

    fn hello(version: u32) -> ToClient {
        ToClient::Hello { version, interval_ms: 500, warnings: vec!["w".into()] }
    }

    #[test]
    fn connects_and_sends_requests() {
        let (path, rx) = fake_daemon("ok", vec![hello(proto::VERSION), ToClient::Snapshot(Box::new(empty())), ToClient::Status("s".into())]);
        let (mut r, w) = Remote::connect(&path).unwrap();
        assert_eq!((w.interval, w.warnings), (Duration::from_millis(500), vec!["w".to_string()]));
        assert!(rx.recv().unwrap().starts_with("{\"Hello\":{\"version\":"));
        r.send(Request::SaveRules).unwrap();
        assert_eq!(rx.recv().unwrap(), "{\"Request\":\"SaveRules\"}\n");
        std::thread::sleep(Duration::from_millis(50));
        assert!(matches!(r.poll().unwrap().as_slice(), [ToClient::Status(s)] if s == "s"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn refuses_other_versions_and_reports_errors() {
        let (path, _rx) = fake_daemon("ver", vec![hello(proto::VERSION + 1)]);
        let e = Remote::connect(&path).err().unwrap().to_string();
        assert!(e.contains("install matching versions"), "{e}");
        let (path2, _rx) = fake_daemon("err", vec![ToClient::Error("not allowed".into())]);
        let e = Remote::connect(&path2).err().unwrap().to_string();
        assert_eq!(e, "netmond: not allowed");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(path2.parent().unwrap());
    }
}
