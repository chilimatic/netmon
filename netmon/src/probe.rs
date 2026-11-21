//! Loads the eBPF object, attaches the TC programs and the socket owner
//! hooks, and reads the maps.

use std::{
    os::unix::fs::DirBuilderExt,
    collections::{BTreeMap, HashSet},
    fs::File,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, bail};
use aya::{
    Ebpf, EbpfLoader, include_bytes_aligned,
    maps::{Array, HashMap, MapData, PerCpuArray, PerCpuHashMap, PerCpuValues, RingBuf},
    programs::{
        CgroupAttachMode, CgroupSock, CgroupSockAddr, SchedClassifier, TcAttachType, TracePoint,
        links::{FdLink, LinkError},
        tc,
    },
    util::{KernelVersion, nr_cpus},
};
use netmon_common::{
    AskEvent, CAPTURE_FLOWS, CAPTURE_IFACE, CAPTURE_OFF, DIR_OUT, CFG_ACTIVE, CFG_COUNT, CFG_DEFAULT, CFG_GEN, CaptureConfig, ConnKey,
    ConnState, FlowKey, FlowStats, GuardKey,
    ListenKey, ListenOwner, MAX_CAPTURE_FLOWS, MAX_EXE_PATH, MAX_FLOWS, MAX_RULES, NameEvent, PacketEvent, RuleEntry, SockOwner,
    TraceCfg, ExeInode,
};

use crate::rules::{GuardEndpoint, addr_bytes};

use crate::ifaces::Iface;

static EBPF_OBJ: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/netmon"));

/// Kernel memory for the per-CPU flow counters, all CPUs together.
const FLOW_VALUE_BUDGET: usize = 64 * 1024 * 1024;
const MIN_FLOWS: u32 = 4_096;

/// Flow map size. Every entry holds one FlowStats per possible CPU, so the
/// size shrinks on hosts with many CPUs: 65 536 entries on up to 25 CPUs,
/// 13 107 on 128 CPUs.
pub fn flow_map_entries(cpus: usize) -> u32 {
    let per_entry = size_of::<FlowStats>() * cpus.max(1);
    let n = (FLOW_VALUE_BUDGET / per_entry).min(MAX_FLOWS as usize) as u32;
    n.max(MIN_FLOWS)
}

/// Kernels before 6.6 have no tcx; TC programs then need a clsact qdisc.
fn needs_clsact() -> bool {
    KernelVersion::current().map(|v| v < KernelVersion::new(6, 6, 0)).unwrap_or(true)
}

pub struct Probe {
    ebpf: Ebpf,
    flows: PerCpuHashMap<MapData, FlowKey, FlowStats>,
    l3_offset: HashMap<MapData, u32, u32>,
    transit: HashMap<MapData, u32, u8>,
    capture_cfg: Array<MapData, CaptureConfig>,
    capture_keys: HashMap<MapData, FlowKey, u8>,
    capture_set: HashSet<FlowKey>,
    /// The last capture key update did not fit in the kernel map.
    capture_full: bool,
    packets: RingBuf<MapData>,
    names: RingBuf<MapData>,
    asks: RingBuf<MapData>,
    drops: PerCpuArray<MapData, u64>,
    sock_owner: HashMap<MapData, u64, SockOwner>,
    listeners: HashMap<MapData, ListenKey, ListenOwner>,
    rule_table: Array<MapData, RuleEntry>,
    rule_cfg: Array<MapData, u32>,
    /// Live table half, as last written to RULE_CFG.
    active: u32,
    generation: u32,
    conns: HashMap<MapData, ConnKey, ConnState>,
    guard: HashMap<MapData, GuardKey, u8>,
    /// Keys as last written to GUARD.
    guard_set: HashSet<GuardKey>,
    rule_hits: PerCpuArray<MapData, u64>,
    exe_id_map: HashMap<MapData, [u8; MAX_EXE_PATH], u32>,
    exe_inodes: HashMap<MapData, ExeInode, u32>,
    /// File of each exe as last written to EXE_INODES.
    inode_of: BTreeMap<String, ExeInode>,
    tgid_exe: HashMap<MapData, u32, u32>,
    /// Exe ids as last written to EXE_IDS.
    exe_ids: BTreeMap<String, u32>,
    cpus: usize,
    attached: HashSet<u32>,
    failed: HashSet<u32>,
    /// Socket owner hooks that did not load or attach.
    pub hook_errors: Vec<String>,
    /// Where the links are pinned, if they are (netmond). Before
    /// `commit_pins` this is the staging directory.
    pins: Option<PathBuf>,
    /// The live pin directory that `commit_pins` replaces.
    pin_target: Option<PathBuf>,
    /// The exec and fork tracepoints run: they keep exe marks current.
    pub exec_tracking: bool,
}

/// Where netmond pins its links. A pinned link stays attached when the
/// process ends, with its program and the maps the program uses: the
/// rules stay in force after a crash. Removing the files detaches them.
pub const PIN_DIR: &str = "/sys/fs/bpf/netmon";

/// Magic number of the BPF file system (statfs f_type).
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

fn is_bpffs(dir: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) else { return false };
    // SAFETY: valid C string and a zeroed statfs buffer.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    unsafe { libc::statfs(c.as_ptr(), &mut st) == 0 && st.f_type as i64 == BPF_FS_MAGIC }
}

/// Where a start pins its links before `commit_pins`: the pins of the
/// running (or crashed) netmond stay in force until then.
/// bpffs refuses names with a dot (EPERM, reserved): no "netmon.new".
fn staging_dir(dir: &Path) -> PathBuf {
    let mut name = dir.file_name().unwrap_or_default().to_os_string();
    name.push("-new");
    dir.with_file_name(name)
}

/// Creates an empty staging directory for the new pins. It removes a
/// staging directory of a start that failed. The live pins stay.
fn prepare_pins(dir: &Path) -> Result<PathBuf, String> {
    let parent = dir.parent().unwrap_or(Path::new("/"));
    if !is_bpffs(parent) {
        return Err(format!("{} is not a BPF file system (mount -t bpf bpf {})", parent.display(), parent.display()));
    }
    let staging = staging_dir(dir);
    match std::fs::remove_dir_all(&staging) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("remove old pins {}: {e}", staging.display())),
    }
    // Root only: whoever can remove a pin detaches a program.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .map_err(|e| format!("create {}: {e}", staging.display()))?;
    Ok(staging)
}

/// Pins a link so it outlives the process. On failure the link is gone
/// (detached): the caller reports the attach as failed.
fn pin<L>(dir: &Path, name: &str, link: L) -> anyhow::Result<()>
where
    FdLink: TryFrom<L, Error = LinkError>,
{
    let path = dir.join(name);
    // A stale file (reused interface index) would make the pin fail.
    let _ = std::fs::remove_file(&path);
    FdLink::try_from(link).context("link cannot be pinned")?.pin(&path).with_context(|| format!("pin {}", path.display()))?;
    Ok(())
}

/// Root of the cgroup v2 tree. Hooks here see every process on the host.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SOCK_HOOKS: [&str; 4] = ["sock_create", "post_bind4", "post_bind6", "sock_release"];
const SOCK_ADDR_HOOKS: [&str; 4] = ["connect4", "connect6", "sendmsg4", "sendmsg6"];

impl Probe {
    /// Loads the programs. With `pin_dir`, every link is pinned there and
    /// stays attached after the process ends, until `unpin`.
    pub fn load(pin_dir: Option<&Path>) -> anyhow::Result<Self> {
        if EBPF_OBJ.is_empty() {
            bail!("binary was built with AYA_BUILD_SKIP=1 and has no eBPF object; rebuild without it");
        }
        let cpus = nr_cpus().map_err(|(path, e)| anyhow::anyhow!("read {path}: {e}"))?;
        let mut ebpf = EbpfLoader::new()
            .map_max_entries("FLOWS", flow_map_entries(cpus))
            .load(EBPF_OBJ)
            .context("load eBPF object (run as root or with CAP_BPF + CAP_NET_ADMIN)")?;
        for name in ["tc_ingress", "tc_egress"] {
            let prog: &mut SchedClassifier = ebpf
                .program_mut(name)
                .with_context(|| format!("program {name} missing"))?
                .try_into()?;
            prog.load().with_context(|| format!("load {name}"))?;
        }
        let flows = PerCpuHashMap::try_from(ebpf.take_map("FLOWS").context("map FLOWS missing")?)?;
        let l3_offset = HashMap::try_from(ebpf.take_map("L3_OFFSET").context("map L3_OFFSET missing")?)?;
        let mut take = |name: &str| ebpf.take_map(name).with_context(|| format!("map {name} missing"));
        let transit = HashMap::try_from(take("TRANSIT_IFACES")?)?;
        let capture_cfg = Array::try_from(take("CAPTURE_CFG")?)?;
        let capture_keys = HashMap::try_from(take("CAPTURE_KEYS")?)?;
        let packets = RingBuf::try_from(take("PACKETS")?)?;
        let names = RingBuf::try_from(take("NAMES")?)?;
        let asks = RingBuf::try_from(take("ASKS")?)?;
        let drops = PerCpuArray::try_from(take("CAPTURE_DROPS")?)?;
        let sock_owner = HashMap::try_from(take("SOCK_OWNER")?)?;
        let listeners = HashMap::try_from(take("LISTENERS")?)?;
        let rule_table = Array::try_from(take("RULES")?)?;
        let rule_cfg = Array::try_from(take("RULE_CFG")?)?;
        let conns = HashMap::try_from(take("CONNS")?)?;
        let guard = HashMap::try_from(take("GUARD")?)?;
        let rule_hits = PerCpuArray::try_from(take("RULE_HITS")?)?;
        let exe_id_map = HashMap::try_from(take("EXE_IDS")?)?;
        let exe_inodes = HashMap::try_from(take("EXE_INODES")?)?;
        let tgid_exe = HashMap::try_from(take("TGID_EXE")?)?;
        let trace_cfg = Array::try_from(take("TRACE_CFG")?)?;
        let mut hook_errors = Vec::new();
        let pins = match pin_dir.map(prepare_pins) {
            Some(Ok(d)) => Some(d),
            Some(Err(e)) => {
                hook_errors.push(format!("rules will not survive a crash: {e}"));
                None
            }
            None => None,
        };
        let pin_target = pins.as_ref().and(pin_dir).map(Path::to_path_buf);
        hook_errors.extend(attach_owner_hooks(&mut ebpf, pins.as_deref()));
        let exec_errors = attach_exec_tracking(&mut ebpf, trace_cfg, pins.as_deref());
        let exec_tracking = exec_errors.is_empty();
        hook_errors.extend(exec_errors);
        Ok(Probe {
            ebpf,
            flows,
            l3_offset,
            transit,
            capture_cfg,
            capture_keys,
            capture_set: HashSet::new(),
            capture_full: false,
            packets,
            names,
            asks,
            drops,
            sock_owner,
            listeners,
            rule_table,
            rule_cfg,
            active: 0,
            generation: 0,
            conns,
            guard,
            guard_set: HashSet::new(),
            rule_hits,
            exe_id_map,
            exe_inodes,
            inode_of: BTreeMap::new(),
            tgid_exe,
            exe_ids: BTreeMap::new(),
            cpus,
            attached: HashSet::new(),
            failed: HashSet::new(),
            hook_errors,
            pins,
            pin_target,
            exec_tracking,
        })
    }

    /// Makes the new pins the live ones. The links of the earlier netmond
    /// detach only now, when the new programs run with their rules: no
    /// moment without a firewall. Until now both sets run, and a packet
    /// passes only if both allow it.
    pub fn commit_pins(&mut self) -> Result<(), String> {
        let (Some(target), Some(staging)) = (self.pin_target.take(), self.pins.clone()) else { return Ok(()) };
        match std::fs::remove_dir_all(&target) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("remove old pins {}: {e}", target.display())),
        }
        std::fs::rename(&staging, &target).map_err(|e| format!("move {} to {}: {e}", staging.display(), target.display()))?;
        self.pins = Some(target);
        Ok(())
    }

    /// Removes the pins: every link detaches when this process ends (at
    /// once for those it no longer holds). For a clean stop, or a failed
    /// start: then only the staging pins go, the live ones stay.
    pub fn unpin(&mut self) {
        if let Some(dir) = self.pins.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    fn tc_pin_name(ifindex: u32, ty: TcAttachType) -> String {
        let side = if ty == TcAttachType::Ingress { "ingress" } else { "egress" };
        format!("tc_{ifindex}_{side}")
    }

    fn attach(&mut self, iface: &Iface) -> anyhow::Result<()> {
        // Missing means 14 (Ethernet). Set or clear it, so a reused index
        // never keeps the offset of an old device.
        if iface.l3_offset != 14 {
            self.l3_offset.insert(iface.index, iface.l3_offset, 0)?;
        } else {
            let _ = self.l3_offset.remove(&iface.index);
        }
        // Containers and VMs send through bridges and veths: the kernel
        // passes forwarded packets there and decides them where they leave.
        if iface.kind.is_virtual() {
            self.transit.insert(iface.index, 1, 0)?;
        } else {
            let _ = self.transit.remove(&iface.index);
        }
        if needs_clsact() {
            // Fails if the qdisc exists, which is fine. A real failure shows
            // up in the attach below.
            let _ = tc::qdisc_add_clsact(&iface.name);
        }
        for (name, ty) in [("tc_ingress", TcAttachType::Ingress), ("tc_egress", TcAttachType::Egress)] {
            if needs_clsact() {
                // A netlink filter of a crashed netmond stays on the
                // interface with its old rules. Remove it first.
                let _ = tc::qdisc_detach_program(iface.name.as_str(), ty, name);
            }
            let prog: &mut SchedClassifier = self.ebpf.program_mut(name).context("program missing")?.try_into()?;
            let id = prog.attach(&iface.name, ty)?;
            // Before tcx (kernel 6.6) the attachment is a netlink filter:
            // no link to pin, but it stays on the interface after a crash
            // by itself. The next start removes it (above).
            if let Some(dir) = &self.pins
                && !needs_clsact()
            {
                pin(dir, &Self::tc_pin_name(iface.index, ty), prog.take_link(id)?)?;
            }
        }
        Ok(())
    }

    /// Makes the kernel key set equal to `capture_set`, which always
    /// mirrors what is really in the map. Keys over MAX_CAPTURE_FLOWS are
    /// left out. That is reported once, not on every update.
    fn set_capture_keys(&mut self, keys: &HashSet<FlowKey>) -> anyhow::Result<()> {
        let gone: Vec<FlowKey> = self.capture_set.difference(keys).copied().collect();
        for k in gone {
            // Delete fails only if the key is missing, which is the goal.
            let _ = self.capture_keys.remove(&k);
            self.capture_set.remove(&k);
        }
        let mut skipped = 0;
        let mut error = None;
        for k in keys.difference(&self.capture_set.clone()) {
            if self.capture_set.len() >= MAX_CAPTURE_FLOWS as usize {
                skipped += 1;
                continue;
            }
            match self.capture_keys.insert(k, 1, 0) {
                Ok(()) => {
                    self.capture_set.insert(*k);
                }
                Err(e) => {
                    skipped += 1;
                    error.get_or_insert(e);
                }
            }
        }
        let was_full = std::mem::replace(&mut self.capture_full, skipped > 0);
        if skipped == 0 || was_full {
            return Ok(());
        }
        match error {
            Some(e) => Err(anyhow::Error::new(e).context(format!("{skipped} flows not captured"))),
            None => bail!("{skipped} flows not captured: limit is {MAX_CAPTURE_FLOWS}"),
        }
    }
}

/// Loads and attaches the socket owner hooks to the root cgroup. They are
/// optional: without them owners come from /proc only.
///
/// aya attaches with bpf_link on kernels >= 5.7. Cgroup links reject the
/// BPF_F_ALLOW_* flags (EINVAL) and always join the cgroup's program list
/// next to others (systemd, container runtimes), so the mode must be
/// `Single`, which sends flags 0. On older kernels aya falls back to
/// BPF_PROG_ATTACH, where `Single` would fail if another program is there:
/// that case shows up as a hook warning.
fn attach_owner_hooks(ebpf: &mut Ebpf, pins: Option<&Path>) -> Vec<String> {
    let cgroup = match File::open(CGROUP_ROOT) {
        Ok(f) => f,
        Err(e) => return vec![format!("owner hooks off: open {CGROUP_ROOT}: {e}")],
    };
    let mut errors = Vec::new();
    for name in SOCK_HOOKS {
        let r = (|| -> anyhow::Result<()> {
            let prog: &mut CgroupSock = ebpf.program_mut(name).context("missing")?.try_into()?;
            prog.load()?;
            let id = prog.attach(&cgroup, CgroupAttachMode::Single)?;
            if let Some(dir) = pins {
                pin(dir, name, prog.take_link(id)?)?;
            }
            Ok(())
        })();
        if let Err(e) = r {
            errors.push(format!("owner hook {name}: {e:#}"));
        }
    }
    for name in SOCK_ADDR_HOOKS {
        let r = (|| -> anyhow::Result<()> {
            let prog: &mut CgroupSockAddr = ebpf.program_mut(name).context("missing")?.try_into()?;
            prog.load()?;
            let id = prog.attach(&cgroup, CgroupAttachMode::Single)?;
            if let Some(dir) = pins {
                pin(dir, name, prog.take_link(id)?)?;
            }
            Ok(())
        })();
        if let Err(e) = r {
            errors.push(format!("owner hook {name}: {e:#}"));
        }
    }
    errors
}

/// Offset of field `name` in a tracefs event format file, e.g. from
/// `\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;`.
pub fn field_offset(format: &str, name: &str) -> Option<u32> {
    format.lines().find_map(|l| {
        let decl = l.split("field:").nth(1)?.split(';').next()?;
        if decl.split_whitespace().last()? != name {
            return None;
        }
        l.split("offset:").nth(1)?.split(';').next()?.trim().parse().ok()
    })
}

fn event_format(category: &str, event: &str) -> std::io::Result<String> {
    let rel = format!("events/{category}/{event}/format");
    std::fs::read_to_string(format!("/sys/kernel/tracing/{rel}"))
        .or_else(|_| std::fs::read_to_string(format!("/sys/kernel/debug/tracing/{rel}")))
}

/// Attaches the exec and fork tracepoints that keep TGID_EXE current.
/// Without them exe rules still work through the /proc scan, but a new
/// process can connect before the next refresh.
fn attach_exec_tracking(ebpf: &mut Ebpf, mut cfg_map: Array<MapData, TraceCfg>, pins: Option<&Path>) -> Vec<String> {
    let mut warnings = Vec::new();
    let r = (|| -> anyhow::Result<()> {
        let exec = event_format("sched", "sched_process_exec").context("read sched_process_exec format")?;
        let task = event_format("task", "task_newtask").context("read task_newtask format")?;
        let cfg = TraceCfg {
            exec_filename: field_offset(&exec, "filename").context("no filename field in sched_process_exec")?,
            newtask_pid: field_offset(&task, "pid").context("no pid field in task_newtask")?,
            newtask_flags: field_offset(&task, "clone_flags").context("no clone_flags field in task_newtask")?,
            ..inode_offsets().unwrap_or_else(|e| {
                warnings.push(format!("exe rules match the started path only, not the file: {e}"));
                TraceCfg::default()
            })
        };
        cfg_map.set(0, cfg, 0)?;
        for (category, name) in [("sched", "sched_process_exec"), ("task", "task_newtask"), ("sched", "sched_process_exit")] {
            let prog: &mut TracePoint = ebpf.program_mut(name).context("missing")?.try_into()?;
            prog.load()?;
            let id = prog.attach(category, name)?;
            if let Some(dir) = pins {
                pin(dir, name, prog.take_link(id)?)?;
            }
        }
        Ok(())
    })();
    match r {
        Ok(()) => warnings,
        Err(e) => vec![format!("exec tracking off (exe blocks act at the next refresh): {e:#}")],
    }
}

/// Offsets for current->mm->exe_file->f_inode->{i_ino, i_sb->s_dev}, from
/// the kernel's BTF.
fn inode_offsets() -> Result<TraceCfg, String> {
    let btf = crate::btf::Btf::from_sys_fs()?;
    let off = |s: &str, m: &str| btf.offset(s, m).ok_or_else(|| format!("no {s}.{m} in kernel BTF"));
    Ok(TraceCfg {
        inode_ok: 1,
        task_mm: off("task_struct", "mm")?,
        mm_exe_file: off("mm_struct", "exe_file")?,
        file_inode: off("file", "f_inode")?,
        inode_ino: off("inode", "i_ino")?,
        inode_sb: off("inode", "i_sb")?,
        sb_dev: off("super_block", "s_dev")?,
        ..TraceCfg::default()
    })
}

/// Device and inode of the file at `path` as the kernel sees them
/// (`super_block.s_dev`, which differs from `stat` on btrfs subvolumes):
/// the file is mapped and the mapping read back from /proc/self/maps.
pub fn exe_inode(path: &str) -> std::io::Result<ExeInode> {
    use std::os::fd::AsRawFd;
    let f = File::open(path)?;
    // SAFETY: a private read-only mapping of one page of an open file.
    let addr = unsafe { libc::mmap(std::ptr::null_mut(), 1, libc::PROT_READ, libc::MAP_PRIVATE, f.as_raw_fd(), 0) };
    if addr == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    let maps = std::fs::read_to_string("/proc/self/maps");
    // SAFETY: the mapping made above.
    unsafe { libc::munmap(addr, 1) };
    let start = format!("{:x}-", addr as usize);
    let line = maps?.lines().find(|l| l.starts_with(&start)).map(str::to_string);
    line.as_deref().and_then(parse_maps_line).ok_or_else(|| std::io::Error::other("mapping not in /proc/self/maps"))
}

/// "7f..-7f.. r--p 00000000 00:2a 1234 /usr/bin/x": dev 00:2a, inode 1234.
fn parse_maps_line(l: &str) -> Option<ExeInode> {
    let mut f = l.split_whitespace();
    let dev = f.nth(3)?;
    let ino = f.next()?.parse().ok()?;
    let (major, minor) = dev.split_once(':')?;
    let (major, minor) = (u32::from_str_radix(major, 16).ok()?, u32::from_str_radix(minor, 16).ok()?);
    Some(ExeInode { dev: major << 20 | minor, _pad: 0, ino })
}

fn exe_key(path: &str) -> anyhow::Result<[u8; MAX_EXE_PATH]> {
    let b = path.as_bytes();
    if b.len() >= MAX_EXE_PATH {
        bail!("exe path longer than {} bytes", MAX_EXE_PATH - 1);
    }
    let mut key = [0u8; MAX_EXE_PATH];
    key[..b.len()].copy_from_slice(b);
    Ok(key)
}

/// What the main loop needs from the kernel side. `Probe` is the real one;
/// tests use a fake.
pub trait Kernel {
    /// Attaches to interfaces not seen before. Returns errors for new
    /// failures only, so a broken interface is reported once.
    fn attach_new(&mut self, ifaces: &[Iface]) -> Vec<String>;
    fn attached_count(&self) -> usize;
    /// Current counters, summed over all CPUs.
    fn snapshot(&self) -> Vec<(FlowKey, FlowStats)>;
    /// Captures every packet on one interface.
    fn capture_iface(&mut self, ifindex: u32) -> anyhow::Result<()>;
    /// Captures packets of the given flows. Call again to update the set.
    fn capture_flows(&mut self, keys: &HashSet<FlowKey>) -> anyhow::Result<()>;
    /// Stops capturing. Packets already in the ring stay there for
    /// `drain_packets`; call `discard_packets` to drop them.
    fn capture_off(&mut self) -> anyhow::Result<()>;
    fn discard_packets(&mut self);
    /// Takes up to `max` captured packets from the ring buffer.
    fn drain_packets(&mut self, max: usize, f: impl FnMut(&PacketEvent));
    /// Takes up to `max` name events (DNS answers, TLS ClientHellos).
    fn drain_names(&mut self, max: usize, f: impl FnMut(&NameEvent));
    /// Takes up to `max` ask events (ask mode).
    fn drain_asks(&mut self, max: usize, f: impl FnMut(&AskEvent));
    /// Answers an asked outbound connection: writes `action` (ACTION_*)
    /// as its verdict for the current rules.
    fn set_verdict(&mut self, key: &ConnKey, action: u8) -> anyhow::Result<()>;
    /// Packets lost because the ring buffer was full, since load. Callers
    /// subtract the value at capture start.
    fn capture_drops(&self) -> u64;
    fn forget(&mut self, keys: &[FlowKey]);
    /// Owner recorded by the cgroup hooks for a socket cookie.
    fn sock_owner(&self, cookie: u64) -> Option<SockOwner>;
    /// Bound sockets recorded by the post_bind hooks: proto, address, owner.
    fn listeners(&self) -> Vec<(u8, SocketAddr, SockOwner)>;
    /// Replaces the rule table and the default action (ACTION_*). Hit
    /// counters of the new table start at 0 and every connection is
    /// decided again. On error the old table stays live.
    fn set_rules(&mut self, rules: &[RuleEntry], exe_ids: &BTreeMap<String, u32>, default: u8)
    -> anyhow::Result<()>;
    /// Direction and verdict the kernel holds for a connection.
    fn conn(&self, key: &ConnKey) -> Option<ConnState>;
    /// Packets and socket calls matched by the rule in `slot` of the live
    /// table, since the last `set_rules`.
    fn rule_hits(&self, slot: usize) -> u64;
    /// Remote endpoints that are never blocked.
    /// Remote endpoints and local TCP ports that are never blocked.
    /// Replaces the guard: new entries first, then the old ones go, so
    /// an entry in both sets is never missing.
    fn set_guard(&mut self, endpoints: &[GuardEndpoint], local_tcp_ports: &[u16]) -> anyhow::Result<()>;
    /// Marks running processes with the exe id of their exe. Returns how
    /// many did not fit into the map.
    fn mark_pids(&mut self, exe_id: u32, pids: &[u32]) -> usize;
    /// Writes direction and owner of connections and listeners that existed
    /// before the start. Connections get an old generation: the kernel
    /// decides them again, but for the right process and direction.
    /// Entries the new programs wrote already stay. Returns how many did
    /// not fit.
    fn seed(&mut self, _conns: &[(ConnKey, u8, u32)], _listeners: &[(ListenKey, SockOwner)]) -> usize {
        0
    }
    /// Reads the file (device, inode) of each exe that rules name again: a
    /// package update replaces the file. Returns an error message.
    fn refresh_exe_inodes(&mut self) -> Option<String> {
        None
    }
}

impl Kernel for Probe {
    fn attach_new(&mut self, ifaces: &[Iface]) -> Vec<String> {
        let mut errors = Vec::new();
        let live: HashSet<u32> = ifaces.iter().map(|i| i.index).collect();
        // Interface indexes of removed devices can be reused: forget them,
        // with their L3 offset.
        for gone in self.attached.iter().chain(&self.failed).filter(|i| !live.contains(i)) {
            let _ = self.l3_offset.remove(gone);
            let _ = self.transit.remove(gone);
            // The kernel detached the links with the device.
            if let Some(dir) = &self.pins {
                for ty in [TcAttachType::Ingress, TcAttachType::Egress] {
                    let _ = std::fs::remove_file(dir.join(Self::tc_pin_name(*gone, ty)));
                }
            }
        }
        self.attached.retain(|i| live.contains(i));
        self.failed.retain(|i| live.contains(i));
        for iface in ifaces {
            if self.attached.contains(&iface.index) || self.failed.contains(&iface.index) {
                continue;
            }
            match self.attach(iface) {
                Ok(()) => {
                    self.attached.insert(iface.index);
                }
                Err(e) => {
                    self.failed.insert(iface.index);
                    errors.push(format!("attach {}: {e:#}", iface.name));
                }
            }
        }
        errors
    }

    fn attached_count(&self) -> usize {
        self.attached.len()
    }

    fn snapshot(&self) -> Vec<(FlowKey, FlowStats)> {
        self.flows
            .iter()
            .flatten()
            .map(|(k, per_cpu)| {
                let mut sum = FlowStats::default();
                for s in per_cpu.iter() {
                    sum.tx_bytes += s.tx_bytes;
                    sum.rx_bytes += s.rx_bytes;
                    sum.tx_pkts += s.tx_pkts;
                    sum.rx_pkts += s.rx_pkts;
                    // Every CPU that sent a packet stored the same cookie.
                    sum.cookie = sum.cookie.max(s.cookie);
                }
                (k, sum)
            })
            .collect()
    }

    fn capture_iface(&mut self, ifindex: u32) -> anyhow::Result<()> {
        self.set_capture_keys(&HashSet::new())?;
        self.capture_cfg.set(0, CaptureConfig { mode: CAPTURE_IFACE, ifindex }, 0)?;
        Ok(())
    }

    fn capture_flows(&mut self, keys: &HashSet<FlowKey>) -> anyhow::Result<()> {
        self.set_capture_keys(keys)?;
        self.capture_cfg.set(0, CaptureConfig { mode: CAPTURE_FLOWS, ifindex: 0 }, 0)?;
        Ok(())
    }

    fn capture_off(&mut self) -> anyhow::Result<()> {
        self.capture_cfg.set(0, CaptureConfig { mode: CAPTURE_OFF, ifindex: 0 }, 0)?;
        self.set_capture_keys(&HashSet::new())
    }

    fn discard_packets(&mut self) {
        while self.packets.next().is_some() {}
    }

    fn drain_packets(&mut self, max: usize, mut f: impl FnMut(&PacketEvent)) {
        for _ in 0..max {
            let Some(item) = self.packets.next() else { break };
            if item.len() >= size_of::<PacketEvent>() {
                // SAFETY: the kernel wrote a PacketEvent; the read is unaligned-safe.
                let ev = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const PacketEvent) };
                f(&ev);
            }
        }
    }

    fn drain_names(&mut self, max: usize, mut f: impl FnMut(&NameEvent)) {
        for _ in 0..max {
            let Some(item) = self.names.next() else { break };
            if item.len() >= size_of::<NameEvent>() {
                // SAFETY: the kernel wrote a NameEvent; the read is unaligned-safe.
                let ev = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const NameEvent) };
                f(&ev);
            }
        }
    }

    fn drain_asks(&mut self, max: usize, mut f: impl FnMut(&AskEvent)) {
        for _ in 0..max {
            let Some(item) = self.asks.next() else { break };
            if item.len() >= size_of::<AskEvent>() {
                // SAFETY: the kernel wrote an AskEvent; the read is unaligned-safe.
                let ev = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const AskEvent) };
                f(&ev);
            }
        }
    }

    fn set_verdict(&mut self, key: &ConnKey, action: u8) -> anyhow::Result<()> {
        // Keep the process the kernel decided for.
        let tgid = self.conns.get(key, 0).map(|s| s.tgid).unwrap_or(0);
        let st = ConnState { generation: self.generation, dir: DIR_OUT, action, exe_known: 1, answered: 1, tgid };
        self.conns.insert(key, st, 0)?;
        Ok(())
    }

    fn capture_drops(&self) -> u64 {
        self.drops.get(&0, 0).map(|v| v.iter().sum()).unwrap_or(0)
    }

    fn forget(&mut self, keys: &[FlowKey]) {
        for k in keys {
            let _ = self.flows.remove(k);
        }
    }

    fn sock_owner(&self, cookie: u64) -> Option<SockOwner> {
        self.sock_owner.get(&cookie, 0).ok()
    }

    fn set_rules(&mut self, rules: &[RuleEntry], exe_ids: &BTreeMap<String, u32>, default: u8) -> anyhow::Result<()> {
        if rules.len() > MAX_RULES as usize {
            bail!("{} rules, the limit is {MAX_RULES}", rules.len());
        }
        // New exe ids first: the new table may name them. Ids are stable
        // while a rule names the exe, so the old table never sees a changed
        // id.
        for (path, id) in exe_ids {
            if self.exe_ids.get(path) != Some(id) {
                self.exe_id_map.insert(exe_key(path)?, *id, 0)?;
            }
        }
        let half = 1 - self.active;
        let base = half * MAX_RULES;
        for (i, r) in rules.iter().enumerate() {
            self.rule_table.set(base + i as u32, r, 0)?;
            self.rule_hits.set(base + i as u32, PerCpuValues::try_from(vec![0u64; self.cpus])?, 0)?;
        }
        self.rule_cfg.set(CFG_COUNT + half, rules.len() as u32, 0)?;
        self.rule_cfg.set(CFG_DEFAULT, default as u32, 0)?;
        self.rule_cfg.set(CFG_ACTIVE, half, 0)?;
        self.active = half;
        // Cached verdicts are stale now. Bumped last, so no packet caches a
        // verdict of the old table under the new generation.
        self.generation = self.generation.wrapping_add(1);
        self.rule_cfg.set(CFG_GEN, self.generation, 0)?;
        // Then drop exe ids no rule names any more, with their marks.
        for (path, id) in &self.exe_ids {
            if !exe_ids.contains_key(path) {
                let _ = self.exe_id_map.remove(&exe_key(path)?);
            }
            if !exe_ids.values().any(|v| v == id) {
                let marked: Vec<u32> =
                    self.tgid_exe.iter().flatten().filter(|(_, v)| v == id).map(|(k, _)| k).collect();
                for tgid in marked {
                    let _ = self.tgid_exe.remove(&tgid);
                }
            }
        }
        self.exe_ids = exe_ids.clone();
        let _ = self.refresh_exe_inodes();
        Ok(())
    }

    fn conn(&self, key: &ConnKey) -> Option<ConnState> {
        self.conns.get(key, 0).ok()
    }

    fn rule_hits(&self, slot: usize) -> u64 {
        let i = self.active * MAX_RULES + slot as u32;
        self.rule_hits.get(&i, 0).map(|v| v.iter().sum()).unwrap_or(0)
    }

    fn set_guard(&mut self, endpoints: &[GuardEndpoint], local_tcp_ports: &[u16]) -> anyhow::Result<()> {
        let mut want = HashSet::new();
        for (ep, proto, dir) in endpoints {
            let (family, addr) = addr_bytes(ep.ip());
            want.insert(GuardKey { addr, port: ep.port(), family, proto: *proto, dir: *dir, _pad: [0; 3] });
        }
        want.extend(local_tcp_ports.iter().filter(|p| **p != 0).map(|p| GuardKey::local_tcp(*p)));
        for k in want.difference(&self.guard_set) {
            self.guard.insert(k, 1, 0)?;
        }
        for k in self.guard_set.difference(&want) {
            let _ = self.guard.remove(k);
        }
        self.guard_set = want;
        Ok(())
    }

    fn mark_pids(&mut self, exe_id: u32, pids: &[u32]) -> usize {
        // A full map leaves the process unmarked: its exe rules do not
        // match. The caller reports it.
        pids.iter().filter(|pid| self.tgid_exe.insert(*pid, exe_id, 0).is_err()).count()
    }

    fn refresh_exe_inodes(&mut self) -> Option<String> {
        let mut want = BTreeMap::new();
        let mut errors = Vec::new();
        for path in self.exe_ids.keys() {
            match exe_inode(path) {
                Ok(k) => {
                    want.insert(path.clone(), k);
                }
                // A missing exe matches by path only, as before.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => errors.push(format!("{path}: {e}")),
            }
        }
        for (path, k) in &self.inode_of {
            if want.get(path) != Some(k) {
                let _ = self.exe_inodes.remove(k);
            }
        }
        for (path, k) in &want {
            if let Some(id) = self.exe_ids.get(path)
                && self.inode_of.get(path) != Some(k)
                && let Err(e) = self.exe_inodes.insert(k, *id, 0)
            {
                errors.push(format!("{path}: {e}"));
            }
        }
        self.inode_of = want;
        (!errors.is_empty()).then(|| format!("exe files not tracked: {}", errors.join("; ")))
    }

    fn seed(&mut self, conns: &[(ConnKey, u8, u32)], listeners: &[(ListenKey, SockOwner)]) -> usize {
        /// Insert only a new key: keep what the programs wrote since attach.
        const BPF_NOEXIST: u64 = 1;
        let stale = self.generation.wrapping_sub(1);
        let mut lost = 0;
        for (key, dir, tgid) in conns {
            let st = ConnState { generation: stale, dir: *dir, action: 0, exe_known: 0, answered: 0, tgid: *tgid };
            if let Err(e) = self.conns.insert(key, st, BPF_NOEXIST) {
                lost += usize::from(!is_exists(&e));
            }
        }
        for (key, owner) in listeners {
            // Cookie 0: sock_release never removes it. A later bind of
            // the same address replaces it.
            if let Err(e) = self.listeners.insert(key, ListenOwner { owner: *owner, cookie: 0 }, BPF_NOEXIST) {
                lost += usize::from(!is_exists(&e));
            }
        }
        lost
    }

    fn listeners(&self) -> Vec<(u8, SocketAddr, SockOwner)> {
        self.listeners
            .iter()
            .flatten()
            .map(|(k, v)| (k.proto, crate::collector::addr(k.family, &k.addr, k.port), v.owner))
            .collect()
    }
}

fn is_exists(e: &aya::maps::MapError) -> bool {
    matches!(e, aya::maps::MapError::SyscallError(s) if s.io_error.raw_os_error() == Some(libc::EEXIST))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_line_gives_kernel_dev_and_inode() {
        let k = parse_maps_line("7f00-7f01 r--p 00000000 00:2a 1234   /usr/bin/x").unwrap();
        assert_eq!(k, ExeInode { dev: 0x2a, _pad: 0, ino: 1234 });
        let k = parse_maps_line("7f00-7f01 r--p 00000000 103:05 99 /x").unwrap();
        assert_eq!(k.dev, 0x103 << 20 | 5, "MKDEV: major << 20");
        let a = exe_inode("/proc/self/exe").unwrap();
        let b = exe_inode(std::env::current_exe().unwrap().to_str().unwrap()).unwrap();
        assert_eq!(a, b, "a link and the path lead to the same file");
    }

    #[test]
    fn staging_name_has_no_dot() {
        assert_eq!(staging_dir(Path::new(PIN_DIR)), Path::new("/sys/fs/bpf/netmon-new"));
    }

    #[test]
    fn pins_only_on_bpffs() {
        let dir = std::env::temp_dir().join(format!("netmon-pins-{}", std::process::id()));
        let e = prepare_pins(&dir.join("netmon")).unwrap_err();
        assert!(e.contains("is not a BPF file system"), "{e}");
        assert!(!dir.join("netmon").exists(), "nothing created");
        assert!(!is_bpffs(Path::new("/proc")));
    }

    #[test]
    fn flow_map_shrinks_with_cpus() {
        assert_eq!(flow_map_entries(1), MAX_FLOWS);
        assert_eq!(flow_map_entries(25), 65_536);
        assert_eq!(flow_map_entries(128), 13_107);
        assert_eq!(flow_map_entries(100_000), MIN_FLOWS);
        // Values never exceed the budget, except at the minimum size.
        for cpus in [1, 8, 64, 256, 1024] {
            let n = flow_map_entries(cpus) as usize;
            assert!(n * cpus * size_of::<FlowStats>() <= FLOW_VALUE_BUDGET || n == MIN_FLOWS as usize);
        }
    }

    #[test]
    fn tracefs_field_offsets() {
        let exec = "name: sched_process_exec\nID: 312\nformat:\n\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\n\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;\n\tfield:pid_t pid;\toffset:12;\tsize:4;\tsigned:1;\n\tfield:pid_t old_pid;\toffset:16;\tsize:4;\tsigned:1;\n";
        assert_eq!(field_offset(exec, "filename"), Some(8));
        assert_eq!(field_offset(exec, "pid"), Some(12), "not old_pid");
        assert_eq!(field_offset(exec, "comm"), None);
        let fork = "\tfield:char parent_comm[16];\toffset:8;\tsize:16;\tsigned:0;\n\tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;\n\tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:0;\n\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;\n";
        assert_eq!(field_offset(fork, "child_pid"), Some(44));
    }

    #[test]
    fn exe_keys_are_nul_padded() {
        let k = exe_key("/usr/bin/curl").unwrap();
        assert_eq!(&k[..13], b"/usr/bin/curl");
        assert!(k[13..].iter().all(|b| *b == 0));
        assert!(exe_key(&"a".repeat(MAX_EXE_PATH)).is_err());
    }
}

