//! `netmond`: runs the monitor as root and serves UIs over a Unix socket.
//!
//! One JSON object per line (see proto). The socket is root:netmon 0660;
//! each peer is checked again with SO_PEERCRED: root or a member of the
//! group. The main thread owns the Monitor; one thread per client reads
//! its requests, another writes to it through a bounded queue. A client
//! that does not keep up is dropped, so it can never stall the monitor.

use std::{
    collections::HashMap,
    ffi::CString,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError},
    },
    time::{Duration, Instant},
};

use anyhow::{Context as _, bail};
use clap::Parser;

use crate::{
    engine::Engine,
    monitor::{self, Monitor},
    probe::PIN_DIR,
    proto::{self, Request, ToClient, ToDaemon},
};

/// Privileged part of netmon: counts traffic, enforces rules and serves
/// the netmon UI over a Unix socket.
#[derive(Parser)]
#[command(version)]
struct DaemonArgs {
    #[command(flatten)]
    monitor: monitor::Args,
    /// Socket the UIs connect to.
    #[arg(long, value_name = "PATH", default_value = proto::DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Group whose members may connect. If it does not exist, only root can.
    #[arg(long, default_value = "netmon")]
    group: String,
}

/// UIs connected at most; more are refused.
const MAX_CLIENTS: usize = 16;
/// Lines queued per client. A snapshot each tick and packets every 50 ms:
/// a client this far behind is stuck.
const CLIENT_QUEUE: usize = 256;
/// Longest wait for a client's hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest the main loop sleeps, so a stop signal is seen soon.
const MAX_WAIT: Duration = Duration::from_millis(500);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

enum Incoming {
    Joined { id: u64, out: SyncSender<Arc<str>> },
    Request { id: u64, req: Request },
    Left(u64),
}

/// Entry point of the `netmond` binary.
pub fn run() -> anyhow::Result<()> {
    let args = DaemonArgs::parse();
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("netmond must run as root");
    }
    let gid = group_id(&args.group);
    if gid.is_none() {
        eprintln!("warning: group {} does not exist: only root can connect", args.group);
    }
    // First the socket: it also makes sure no other netmond runs, whose
    // pins the load below would remove.
    let listener = bind(&args.socket, gid)?;
    let (mon, warnings) = match Monitor::new(&args.monitor, Some(Path::new(PIN_DIR))) {
        Ok(m) => m,
        Err(e) => {
            let _ = std::fs::remove_file(&args.socket);
            return Err(e);
        }
    };
    // Start messages: problems and the rules file summary.
    for w in &warnings {
        eprintln!("netmond: {w}");
    }
    eprintln!("netmond: listening on {}", args.socket.display());
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: the handler only stores to an atomic.
        unsafe { libc::signal(sig, on_signal as *const () as libc::sighandler_t) };
    }
    let (tx, rx) = mpsc::channel();
    let count = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || accept(listener, gid, tx, count));
    let mut engine = Engine::new(mon, args.monitor.interval());
    let result = serve(&mut engine, &rx, &warnings);
    // A clean stop: the kernel side goes with the process. Only a crash
    // leaves the pins, and with them the rules.
    engine.mon.probe.unpin();
    let _ = std::fs::remove_file(&args.socket);
    eprintln!("netmond: stopped, rules removed");
    result
}

fn serve(engine: &mut Engine, rx: &Receiver<Incoming>, warnings: &[String]) -> anyhow::Result<()> {
    let mut clients: HashMap<u64, SyncSender<Arc<str>>> = HashMap::new();
    while !STOP.load(Ordering::Relaxed) {
        match rx.recv_timeout(engine.wait().min(MAX_WAIT)) {
            Ok(Incoming::Joined { id, out }) => {
                let hello = ToClient::Hello {
                    version: proto::VERSION,
                    interval_ms: engine.interval().as_millis() as u64,
                    warnings: warnings.to_vec(),
                };
                for m in [hello, engine.snapshot()] {
                    let _ = out.try_send(proto::line(&m).into());
                }
                clients.insert(id, out);
            }
            Ok(Incoming::Request { id, req }) => {
                for m in engine.request(req) {
                    match m {
                        ToClient::Reply { .. } => send(&mut clients, Some(id), &m),
                        _ => send(&mut clients, None, &m),
                    }
                }
            }
            Ok(Incoming::Left(id)) => {
                clients.remove(&id);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => bail!("socket listener stopped"),
        }
        let msgs = engine.step(Instant::now());
        let t = Instant::now();
        for m in &msgs {
            if let ToClient::Status(s) = m {
                eprintln!("netmond: {s}");
            }
            send(&mut clients, None, m);
        }
        if !msgs.is_empty() {
            engine.mon.prof.add("send to clients (JSON)", t);
        }
    }
    Ok(())
}

/// Sends to one client or all. Drops clients whose queue is full or gone.
fn send(clients: &mut HashMap<u64, SyncSender<Arc<str>>>, to: Option<u64>, msg: &ToClient) {
    if clients.is_empty() {
        return;
    }
    let line: Arc<str> = proto::line(msg).into();
    clients.retain(|id, out| {
        if to.is_some_and(|t| t != *id) {
            return true;
        }
        match out.try_send(line.clone()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                eprintln!("netmond: client {id} too slow, dropped");
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    });
}

/// Binds the socket: root:group 0660, or root 0600 without the group. A
/// socket left by a crashed daemon is replaced; a running daemon or any
/// other file at the path is an error.
fn bind(path: &Path, gid: Option<u32>) -> anyhow::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            if UnixStream::connect(path).is_ok() {
                bail!("netmond already runs: {} answers", path.display());
            }
            std::fs::remove_file(path).with_context(|| format!("remove stale {}", path.display()))?;
        }
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("check {}", path.display())),
    }
    // Created 0600: nobody else can connect before the group is set.
    // SAFETY: umask has no preconditions; restored right after.
    let old = unsafe { libc::umask(0o177) };
    let bound = UnixListener::bind(path);
    unsafe { libc::umask(old) };
    let listener = bound.with_context(|| format!("bind {}", path.display()))?;
    if let Some(gid) = gid {
        std::os::unix::fs::chown(path, Some(0), Some(gid)).with_context(|| format!("chown {}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    }
    Ok(listener)
}

fn group_id(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    // SAFETY: valid C string; the result is read at once, before any
    // other call that could reuse getgrnam's static buffer (the accept
    // thread starts later).
    let g = unsafe { libc::getgrnam(c.as_ptr()) };
    // SAFETY: non-null pointer to a group entry.
    (!g.is_null()).then(|| unsafe { (*g).gr_gid })
}

fn accept(listener: UnixListener, gid: Option<u32>, tx: Sender<Incoming>, count: Arc<AtomicUsize>) {
    let mut next_id = 0u64;
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        next_id += 1;
        let (id, tx, count) = (next_id, tx.clone(), count.clone());
        std::thread::spawn(move || {
            if let Err(e) = client(stream, id, gid, &tx, &count) {
                eprintln!("netmond: client {id}: {e:#}");
            }
        });
    }
}

/// Serves one connection: checks the peer, reads its hello, starts its
/// writer, then forwards its requests until it leaves.
fn client(stream: UnixStream, id: u64, gid: Option<u32>, tx: &Sender<Incoming>, count: &AtomicUsize) -> anyhow::Result<()> {
    let refuse = |mut s: &UnixStream, why: &str| {
        let _ = s.write_all(proto::line(&ToClient::Error(why.into())).as_bytes());
    };
    let cred = peer_cred(&stream)?;
    if !allowed(&cred, gid) {
        refuse(&stream, "not allowed: root or group netmon only");
        bail!("refused uid {} pid {}", cred.uid, cred.pid);
    }
    if count.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
        count.fetch_sub(1, Ordering::SeqCst);
        refuse(&stream, "too many clients");
        bail!("refused: too many clients");
    }
    let result = session(stream, id, tx);
    count.fetch_sub(1, Ordering::SeqCst);
    let _ = tx.send(Incoming::Left(id));
    result
}

fn session(stream: UnixStream, id: u64, tx: &Sender<Incoming>) -> anyhow::Result<()> {
    let mut lines = BufReader::new(stream.try_clone()?);
    stream.set_read_timeout(Some(HELLO_TIMEOUT))?;
    match read_request(&mut lines)? {
        Some(ToDaemon::Hello { version }) if version == proto::VERSION => {}
        Some(ToDaemon::Hello { version }) => {
            let why = format!("protocol {version} not supported, netmond speaks {}", proto::VERSION);
            let _ = (&stream).write_all(proto::line(&ToClient::Error(why.clone())).as_bytes());
            bail!(why);
        }
        _ => bail!("no hello"),
    }
    stream.set_read_timeout(None)?;
    let (out, queue) = mpsc::sync_channel::<Arc<str>>(CLIENT_QUEUE);
    let writer = stream.try_clone()?;
    std::thread::spawn(move || write_lines(writer, queue));
    tx.send(Incoming::Joined { id, out })?;
    while let Some(msg) = read_request(&mut lines)? {
        match msg {
            ToDaemon::Request(req) => tx.send(Incoming::Request { id, req })?,
            ToDaemon::Hello { .. } => bail!("second hello"),
        }
    }
    Ok(())
}

/// Writes queued lines until the queue closes (client dropped) or the
/// socket fails; then shuts the socket so the reader ends too.
fn write_lines(mut stream: UnixStream, queue: Receiver<Arc<str>>) {
    for line in queue {
        if stream.write_all(line.as_bytes()).is_err() {
            break;
        }
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// The next line, parsed. None at the end of the stream. Lines longer
/// than MAX_REQUEST_LINE and malformed lines are errors.
fn read_request(r: &mut BufReader<UnixStream>) -> anyhow::Result<Option<ToDaemon>> {
    let mut buf = Vec::new();
    let n = r.by_ref().take(proto::MAX_REQUEST_LINE).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        bail!("line too long or cut off");
    }
    Ok(Some(serde_json::from_slice(&buf).context("malformed line")?))
}

fn peer_cred(s: &UnixStream) -> anyhow::Result<libc::ucred> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: valid socket fd; cred and len describe a ucred-sized buffer.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error()).context("SO_PEERCRED");
    }
    Ok(cred)
}

/// Root, or a member of the group: primary group from the credentials,
/// supplementary groups from /proc/<pid>/status. The socket's file mode
/// already enforces the same; this is the second check.
fn allowed(cred: &libc::ucred, gid: Option<u32>) -> bool {
    if cred.uid == 0 {
        return true;
    }
    let Some(gid) = gid else { return false };
    if cred.gid == gid {
        return true;
    }
    let status = std::fs::read_to_string(format!("/proc/{}/status", cred.pid)).unwrap_or_default();
    in_groups(&status, gid)
}

fn in_groups(status: &str, gid: u32) -> bool {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .is_some_and(|g| g.split_whitespace().any(|x| x.parse() == Ok(gid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supplementary_groups() {
        let status = "Name:\tbash\nGid:\t1000\t1000\t1000\t1000\nGroups:\t10 973 1000 \n";
        assert!(in_groups(status, 973));
        assert!(!in_groups(status, 97));
        assert!(!in_groups("Name:\tx\n", 973));
        let me = libc::ucred { pid: std::process::id() as i32, uid: 1000, gid: 1000 };
        assert!(!allowed(&me, None), "no group: root only");
        assert!(allowed(&me, Some(1000)));
        assert!(allowed(&libc::ucred { uid: 0, ..me }, None));
    }

    #[test]
    fn request_lines_are_limited_and_checked() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut r = BufReader::new(b);
        let mut w = &a;
        w.write_all(proto::line(&ToDaemon::Hello { version: 1 }).as_bytes()).unwrap();
        w.write_all(b"{\"Request\":\"SaveRules\"}\n").unwrap();
        w.write_all(b"not json\n").unwrap();
        assert_eq!(read_request(&mut r).unwrap(), Some(ToDaemon::Hello { version: 1 }));
        assert_eq!(read_request(&mut r).unwrap(), Some(ToDaemon::Request(Request::SaveRules)));
        assert!(read_request(&mut r).is_err(), "malformed");
        let long = vec![b'x'; proto::MAX_REQUEST_LINE as usize + 10];
        let t = std::thread::spawn(move || {
            let _ = (&a).write_all(&long);
        });
        assert!(read_request(&mut r).is_err(), "too long");
        drop(r);
        t.join().unwrap();
    }

    #[test]
    fn bind_replaces_stale_socket_only() {
        let dir = std::env::temp_dir().join(format!("netmond-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let l = bind(&path, None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "no group: owner only");
        assert!(bind(&path, None).is_err(), "a listening daemon is not replaced");
        drop(l);
        bind(&path, None).expect("stale socket replaced");
        let file = dir.join("plain");
        std::fs::write(&file, b"x").unwrap();
        assert!(bind(&file, None).is_err(), "not a socket");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
