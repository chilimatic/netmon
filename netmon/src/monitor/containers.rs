//! Socket tables of containers, read in a background thread.

use super::*;

/// The container process behind a connection without a socket on the
/// host, by remote end and local port.
pub(crate) fn container_of(tables: &[procmap::ContainerTable], key: &netmon_common::ConnKey) -> Option<Owner> {
    let remote = std::net::SocketAddr::new(ask::remote(key), key.remote_port);
    let any_local = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), key.local_port);
    tables.iter().find_map(|t| t.lookup(key.proto, any_local, remote)).map(|(o, _)| o.clone())
}

/// Reads container socket tables in a thread: one read takes 150-250 ms on
/// a host with 30 namespaces, too long for the UI loop. Each `()` sent asks
/// for one read; the tables come back on the other channel.
pub(crate) type ContainerResult = (Vec<procmap::ContainerTable>, Duration);

pub(crate) fn container_reader() -> (std::sync::mpsc::SyncSender<()>, std::sync::mpsc::Receiver<ContainerResult>) {
    let (req_tx, req_rx) = std::sync::mpsc::sync_channel::<()>(1);
    let (res_tx, res_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut owners = OwnerCache::default();
        let mut namespaces = Vec::new();
        let mut scanned: Option<Instant> = None;
        // Ends when the Monitor (the sender) is dropped.
        while req_rx.recv().is_ok() {
            let start = Instant::now();
            if scanned.is_none_or(|t| t.elapsed() >= NETNS_RESCAN) {
                namespaces = netns::scan();
                scanned = Some(Instant::now());
            }
            let tables = procmap::read_containers(&mut owners, &namespaces);
            if res_tx.send((tables, start.elapsed())).is_err() {
                break;
            }
        }
    });
    (req_tx, res_rx)
}

impl<K: Kernel> Monitor<K> {
    /// Asks the container reader for fresh tables if the last request is
    /// older than `max_age`, and takes any tables it has finished.
    /// Takes the tables the reader has finished.
    pub(crate) fn take_containers(&mut self) {
        while let Ok((tables, took)) = self.containers_rx.try_recv() {
            self.containers = tables;
            self.prof.add_time("container tables (thread)", took);
        }
    }

    /// Returns true if it asked for a new read.
    pub(crate) fn refresh_containers(&mut self, now: Instant, max_age: Duration) -> bool {
        self.take_containers();
        if self.containers_asked.is_some_and(|t| now.duration_since(t) < max_age) {
            return false;
        }
        // The reader is busy with the previous request if it is still
        // queued; asking twice only repeats the work.
        let _ = self.containers_tx.try_send(());
        self.containers_asked = Some(now);
        true
    }
}
