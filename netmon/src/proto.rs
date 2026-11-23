//! What the monitor and a UI exchange: requests from the UI, snapshots and
//! captured packets from the monitor. Plain data with serde, so the same
//! types run in one process (local mode) and over a socket (daemon).

use std::time::SystemTime;

use crate::{
    app::Answer,
    ask::{Dest, Prompt, Scope},
    capture::Target,
    collector::Collector,
    ifaces::Names,
    rules::{BlockTarget, Rules},
};

/// Version of this protocol. Client and daemon must have the same.
pub const VERSION: u32 = 5;

/// Where `netmond` listens.
pub const DEFAULT_SOCKET: &str = "/run/netmon.sock";

/// Longest line a client may send. Requests are small; a longer line ends
/// the connection.
pub const MAX_REQUEST_LINE: u64 = 64 * 1024;

/// One line from a UI to the daemon. The first must be `Hello`.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ToDaemon {
    Hello { version: u32 },
    Request(Request),
}

/// One line from the monitor to a UI.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum ToClient {
    /// First line after the client's hello.
    Hello {
        version: u32,
        /// Refresh interval, for the graph's time axis.
        interval_ms: u64,
        /// Problems found at start (interfaces, rules file).
        warnings: Vec<String>,
    },
    /// The connection ends: wrong version or not allowed.
    Error(String),
    Snapshot(Box<Snapshot>),
    Packets(Vec<RawPacket>),
    /// Result of this client's request.
    Reply { req: Request, msg: String },
    /// A problem while running, for every client.
    Status(String),
    /// A program bound a port that other hosts can reach.
    Listener(crate::monitor::listen::NewListener),
}

/// One JSON line with its newline.
pub fn line<T: serde::Serialize>(msg: &T) -> String {
    // These types cannot fail to serialize: map keys are strings or
    // integers, and no custom serializer returns an error.
    let mut s = serde_json::to_string(msg).unwrap_or_default();
    s.push('\n');
    s
}

/// A change the UI asks for. Rows are named by what they are (address,
/// exe, rule id, question id), never by their position on the screen: the
/// monitor's data may have changed since the UI drew it.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Request {
    /// Block, or remove the block rule if it exists.
    ToggleBlock(BlockTarget),
    RemoveRule(u32),
    /// Rule `id` ends `secs` from now; None: it never ends.
    SetRuleTimer { id: u32, secs: Option<u64> },
    /// Block a hostname pattern (`name` or `*.domain`).
    BlockHost { pattern: String, comment: String },
    /// Remove a host block or a host block list.
    RemoveHost(u32),
    /// Read the host block lists again.
    ReloadBlocklists,
    SaveRules,
    /// Answer a question for one of its destinations.
    Answer { question: u64, dest: DestId, scope: Scope, answer: Answer },
    StartCapture(Target),
    StopCapture,
}

/// One destination of a question.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DestId {
    pub remote: std::net::IpAddr,
    pub port: u16,
    pub proto: u8,
}

/// Everything a UI shows, taken after each change.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub collector: Collector,
    pub names: Names,
    pub rules: Rules,
    /// Open questions, oldest first.
    pub questions: Vec<Prompt>,
    pub capture: Option<CaptureInfo>,
}

/// The running or last capture. The packets come separately.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CaptureInfo {
    /// Counts up with each start, so a UI sees a restart of the same target.
    pub id: u64,
    pub target: Target,
    pub running: bool,
    /// Packets lost because the kernel ring buffer was full.
    pub dropped: u64,
}

/// One captured packet as it leaves the monitor. The UI decodes it.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RawPacket {
    pub time: SystemTime,
    pub ifindex: u32,
    pub egress: bool,
    /// Original length on the wire, including the Ethernet header.
    pub orig_len: u32,
    /// Ethernet-framed bytes.
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

impl From<&Dest> for DestId {
    fn from(d: &Dest) -> Self {
        DestId { remote: d.remote, port: d.port, proto: d.proto }
    }
}

/// Bytes as one base64 string: JSON arrays of numbers are four times as
/// long.
mod base64_bytes {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        STANDARD.decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// An `Instant` as its age in milliseconds. Instants are only meaningful
/// inside one process; the age is the same on both sides.
pub mod age {
    use std::time::{Duration, Instant};

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(t: &Instant, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(t.elapsed().as_millis() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Instant, D::Error> {
        let ms = u64::deserialize(d)?;
        let now = Instant::now();
        Ok(now.checked_sub(Duration::from_millis(ms)).unwrap_or(now))
    }
}

/// A `&'static str` label read back from a string. Labels come from a
/// small fixed set (TCP states, name sources), so each distinct value is
/// kept once; past a limit unknown values read as "?".
pub mod label {
    use std::{
        collections::HashSet,
        sync::{Mutex, OnceLock},
    };

    use serde::{Deserialize, Deserializer};

    const MAX_LABELS: usize = 64;

    /// A label. The alias also keeps serde from borrowing the field from
    /// the input, which a plain `&'static str` field would.
    pub type Label = &'static str;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<&'static str, D::Error> {
        let s = String::deserialize(d)?;
        Ok(intern(&s))
    }

    fn intern(s: &str) -> &'static str {
        static LABELS: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
        let mut set = LABELS.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
        if let Some(l) = set.get(s) {
            return l;
        }
        if set.len() >= MAX_LABELS {
            return "?";
        }
        let l: &'static str = Box::leak(s.to_owned().into_boxed_str());
        set.insert(l);
        l
    }
}

/// A map as a list of its values: JSON object keys must be strings, and
/// each value already holds its key.
pub mod values {
    use std::{collections::HashMap, hash::Hash};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub trait Keyed {
        type Key: Eq + Hash;
        fn key(&self) -> Self::Key;
    }

    pub fn serialize<K, V: Serialize, S: Serializer>(m: &HashMap<K, V>, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(m.values())
    }

    pub fn deserialize<'de, V, D>(d: D) -> Result<HashMap<V::Key, V>, D::Error>
    where
        V: Keyed + serde::de::DeserializeOwned,
        D: Deserializer<'de>,
    {
        Ok(Vec::<V>::deserialize(d)?.into_iter().map(|v| (v.key(), v)).collect())
    }
}
