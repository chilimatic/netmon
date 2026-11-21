//! `netmond`: runs the monitor as root and serves UIs over a Unix socket.
//!
//! One JSON object per line (see proto). The socket is root:netmon 0660;
//! each peer is checked again with SO_PEERCRED: root or a member of the
//! group. The main thread owns the Monitor; one thread per client reads
//! its requests, another writes to it from an `Outbox`. A new snapshot
//! replaces an unsent one, so a slow client costs one snapshot of memory.
//! A client whose other lines pile up, or that does not read for
//! WRITE_TIMEOUT, is dropped: it can never stall the monitor.

use std::{
    collections::{HashMap, VecDeque},
    ffi::CString,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        io::{AsRawFd, FromRawFd, OwnedFd},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError},
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

/// Local TCP port netmond never blocks unless --guard-port says otherwise.
const DEFAULT_GUARD_PORT: u16 = 22;
/// UIs connected at most; more are refused.
const MAX_CLIENTS: usize = 16;
/// Lines other than snapshots queued per client (packets every 50 ms,
/// replies, status): a client this far behind is stuck.
const CLIENT_QUEUE: usize = 256;
/// Bytes of those lines queued per client at most.
const CLIENT_BYTES: usize = 16 << 20;
/// A client that takes no data for this long is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Requests and client events waiting for the main loop. A client that
/// sends faster waits: its reader thread blocks.
const REQUEST_QUEUE: usize = 64;
/// Requests carried out before one snapshot goes out.
const REQUEST_BATCH: usize = 32;
/// Longest wait for a client's hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest the main loop sleeps, so a stop signal is seen soon.
const MAX_WAIT: Duration = Duration::from_millis(500);

static STOP: AtomicBool = AtomicBool::new(false);
static HUP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// SIGHUP (a closed terminal, `kill -HUP`) must not remove the rules.
extern "C" fn on_hup(_: libc::c_int) {
    HUP.store(true, Ordering::Relaxed);
}

/// Lines waiting for one client.
#[derive(Default)]
struct Outbox {
    state: Mutex<OutState>,
    ready: Condvar,
}

#[derive(Default)]
struct OutState {
    /// The line and whether it is a snapshot.
    lines: VecDeque<(Arc<str>, bool)>,
    /// Bytes of the lines that are not snapshots.
    bytes: usize,
    closed: bool,
}

impl Outbox {
    /// Queues a line. A snapshot replaces an unsent older snapshot. False
    /// if the client is gone or too far behind: drop it.
    fn push(&self, line: Arc<str>, snapshot: bool) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.closed {
            return false;
        }
        if snapshot {
            s.lines.retain(|(_, snap)| !snap);
        } else {
            let others = s.lines.iter().filter(|(_, snap)| !snap).count();
            if others >= CLIENT_QUEUE || s.bytes + line.len() > CLIENT_BYTES {
                return false;
            }
            s.bytes += line.len();
        }
        s.lines.push_back((line, snapshot));
        self.ready.notify_one();
        true
    }

    /// The next line. Waits for one. None after `close`.
    fn pop(&self) -> Option<Arc<str>> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if s.closed {
                return None;
            }
            if let Some((line, snapshot)) = s.lines.pop_front() {
                if !snapshot {
                    s.bytes -= line.len();
                }
                return Some(line);
            }
            s = self.ready.wait(s).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn close(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.closed = true;
        s.lines.clear();
        self.ready.notify_all();
    }
}

enum Incoming {
    Joined { id: u64, out: Arc<Outbox> },
    Request { id: u64, req: Request },
    Left(u64),
}

/// Entry point of the `netmond` binary.
pub fn run() -> anyhow::Result<()> {
    let mut args = DaemonArgs::parse();
    // A daemon started by systemd has no SSH session to guard: guard the
    // SSH port, so a rule can never lock the admin out.
    if args.monitor.guard_ports.is_empty() {
        args.monitor.guard_ports.push(DEFAULT_GUARD_PORT);
    }
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
    for sig in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: the handler only stores to an atomic.
        unsafe { libc::signal(sig, on_signal as *const () as libc::sighandler_t) };
    }
    // SAFETY: as above.
    unsafe { libc::signal(libc::SIGHUP, on_hup as *const () as libc::sighandler_t) };
    let (tx, rx) = mpsc::sync_channel(REQUEST_QUEUE);
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
    let mut clients: HashMap<u64, Arc<Outbox>> = HashMap::new();
    while !STOP.load(Ordering::Relaxed) {
        if HUP.swap(false, Ordering::Relaxed) {
            eprintln!("netmond: SIGHUP ignored: the rules stay; systemctl restart netmond reloads the rules file");
        }
        let mut next = rx.recv_timeout(engine.wait().min(MAX_WAIT));
        // Requests that wait together get one snapshot, not one each.
        let mut changed = false;
        for _ in 0..REQUEST_BATCH {
            match next {
                Ok(Incoming::Joined { id, out }) => {
                    let hello = ToClient::Hello {
                        version: proto::VERSION,
                        interval_ms: engine.interval().as_millis() as u64,
                        warnings: warnings.to_vec(),
                    };
                    out.push(proto::line(&hello).into(), false);
                    out.push(proto::line(&engine.snapshot()).into(), true);
                    clients.insert(id, out);
                }
                Ok(Incoming::Request { id, req }) => {
                    changed = true;
                    for m in engine.request_quiet(req) {
                        let to = matches!(m, ToClient::Reply { .. }).then_some(id);
                        send(&mut clients, to, &m);
                    }
                }
                Ok(Incoming::Left(id)) => {
                    if let Some(out) = clients.remove(&id) {
                        out.close();
                    }
                }
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => bail!("socket listener stopped"),
            }
            next = match rx.try_recv() {
                Ok(m) => Ok(m),
                Err(TryRecvError::Empty) => Err(RecvTimeoutError::Timeout),
                Err(TryRecvError::Disconnected) => Err(RecvTimeoutError::Disconnected),
            };
        }
        if changed {
            send(&mut clients, None, &engine.snapshot());
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
    for out in clients.values() {
        out.close();
    }
    Ok(())
}

/// Sends to one client or all. Drops clients that are gone or too far
/// behind.
fn send(clients: &mut HashMap<u64, Arc<Outbox>>, to: Option<u64>, msg: &ToClient) {
    if clients.is_empty() {
        return;
    }
    let line: Arc<str> = proto::line(msg).into();
    let snapshot = matches!(msg, ToClient::Snapshot(_));
    clients.retain(|id, out| {
        if to.is_some_and(|t| t != *id) {
            return true;
        }
        if out.push(line.clone(), snapshot) {
            return true;
        }
        eprintln!("netmond: client {id} gone or too slow, dropped");
        out.close();
        false
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
        open_group(path, gid)?;
    }
    Ok(listener)
}

/// Gives the group access to the socket just bound at `path`. Works on
/// the file itself, never through a symlink: with --socket in a directory
/// others can write, a swapped path must not hand some other file to the
/// group.
fn open_group(path: &Path, gid: u32) -> anyhow::Result<()> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: valid C string. O_PATH opens without reading or following.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("open {}", path.display()));
    }
    // SAFETY: fd is a new descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: zeroed stat buffer, valid fd.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error()).context("fstat socket");
    }
    // Our socket is root's: anything else was put there by someone else.
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK || st.st_uid != 0 {
        bail!("{} changed after bind: not netmond's socket", path.display());
    }
    // SAFETY: valid fd and empty C string with AT_EMPTY_PATH.
    if unsafe { libc::fchownat(fd.as_raw_fd(), c"".as_ptr(), 0, gid, libc::AT_EMPTY_PATH) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("chown {}", path.display()));
    }
    // chmod through the descriptor: /proc/self/fd/N names this inode.
    std::fs::set_permissions(format!("/proc/self/fd/{}", fd.as_raw_fd()), std::fs::Permissions::from_mode(0o660))
        .with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
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

fn accept(listener: UnixListener, gid: Option<u32>, tx: SyncSender<Incoming>, count: Arc<AtomicUsize>) {
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
fn client(stream: UnixStream, id: u64, gid: Option<u32>, tx: &SyncSender<Incoming>, count: &AtomicUsize) -> anyhow::Result<()> {
    let refuse = |mut s: &UnixStream, why: &str| {
        let _ = s.write_all(proto::line(&ToClient::Error(why.into())).as_bytes());
    };
    let cred = peer_cred(&stream)?;
    if !allowed(&cred, &peer_groups(&stream)?, gid) {
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

fn session(stream: UnixStream, id: u64, tx: &SyncSender<Incoming>) -> anyhow::Result<()> {
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
    let out = Arc::new(Outbox::default());
    let writer = stream.try_clone()?;
    writer.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let queue = out.clone();
    std::thread::spawn(move || write_lines(writer, &queue));
    tx.send(Incoming::Joined { id, out })?;
    while let Some(msg) = read_request(&mut lines)? {
        match msg {
            ToDaemon::Request(req) => tx.send(Incoming::Request { id, req })?,
            ToDaemon::Hello { .. } => bail!("second hello"),
        }
    }
    Ok(())
}

/// Writes queued lines until the outbox closes (client dropped) or the
/// socket fails or times out; then shuts the socket so the reader ends
/// too, and the main loop drops the client.
fn write_lines(mut stream: UnixStream, out: &Outbox) {
    while let Some(line) = out.pop() {
        if stream.write_all(line.as_bytes()).is_err() {
            break;
        }
    }
    out.close();
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

/// Groups of the peer when it connected (SO_PEERGROUPS, kernel 4.13).
/// Taken from the socket, not from /proc: no pid reuse race.
fn peer_groups(s: &UnixStream) -> anyhow::Result<Vec<u32>> {
    let mut groups = vec![0 as libc::gid_t; 64];
    loop {
        let mut len = (groups.len() * size_of::<libc::gid_t>()) as libc::socklen_t;
        // SAFETY: valid socket fd; groups and len describe the buffer.
        let r = unsafe {
            libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERGROUPS, groups.as_mut_ptr().cast(), &mut len)
        };
        if r == 0 {
            groups.truncate(len as usize / size_of::<libc::gid_t>());
            return Ok(groups);
        }
        let e = std::io::Error::last_os_error();
        // ERANGE: len holds the size needed.
        if e.raw_os_error() != Some(libc::ERANGE) || groups.len() >= 65_536 {
            return Err(e).context("SO_PEERGROUPS");
        }
        groups.resize((len as usize / size_of::<libc::gid_t>()).max(groups.len() * 2), 0);
    }
}

/// Root, or a member of the group (primary or supplementary). The
/// socket's file mode already enforces the same; this is the second check.
fn allowed(cred: &libc::ucred, groups: &[u32], gid: Option<u32>) -> bool {
    if cred.uid == 0 {
        return true;
    }
    let Some(gid) = gid else { return false };
    cred.gid == gid || groups.contains(&gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supplementary_groups() {
        let me = libc::ucred { pid: std::process::id() as i32, uid: 1000, gid: 1000 };
        assert!(!allowed(&me, &[973], None), "no group: root only");
        assert!(allowed(&me, &[], Some(1000)), "primary group");
        assert!(allowed(&me, &[10, 973], Some(973)), "supplementary group");
        assert!(!allowed(&me, &[10, 973], Some(97)));
        assert!(allowed(&libc::ucred { uid: 0, ..me }, &[], None));
        let (a, _b) = UnixStream::pair().unwrap();
        peer_groups(&a).expect("SO_PEERGROUPS works on a socket pair");
    }

    #[test]
    fn outbox_keeps_one_snapshot_and_limits_the_rest() {
        let out = Outbox::default();
        assert!(out.push("s1".into(), true));
        assert!(out.push("p1".into(), false));
        assert!(out.push("s2".into(), true));
        assert_eq!(out.pop().as_deref(), Some("p1"));
        assert_eq!(out.pop().as_deref(), Some("s2"), "older snapshot replaced");
        for _ in 0..CLIENT_QUEUE {
            assert!(out.push("p".into(), false));
        }
        assert!(!out.push("p".into(), false), "too far behind");
        assert!(out.push("s3".into(), true), "a snapshot always fits");
        out.close();
        assert_eq!(out.pop(), None);
        assert!(!out.push("p".into(), false), "closed");
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
