//! `netmon-notify`: shows each question of netmond as a desktop
//! notification with buttons, and sends the answer that the user clicks.
//! Runs as the desktop user (a member of group `netmon`), because netmond
//! runs as root and cannot reach the user's session bus.
//!
//! The notifications come from `notify-send` (libnotify 0.8 or later): one
//! child process per question. It prints the notification id, then the name
//! of the clicked button. When the question goes away (answered in the
//! TUI, or timed out), a short notification replaces it. A program that
//! binds a port other hosts can reach also gets a notification.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, Sender},
    },
    time::Duration,
};

use anyhow::Context as _;
use clap::Parser;

use crate::{
    app::Answer,
    ask::{Prompt, Scope},
    proto::{self, DestId, Request, ToClient},
    remote::Remote,
    rules::proto_name,
};

/// Shows the questions of netmond (ask mode) as desktop notifications.
#[derive(Parser)]
#[command(version)]
struct NotifyArgs {
    /// Socket of netmond.
    #[arg(long, value_name = "PATH", default_value = proto::DEFAULT_SOCKET)]
    socket: PathBuf,
    /// No notifications about new listeners.
    #[arg(long)]
    no_listeners: bool,
}

/// How often the notifier reads netmond's messages.
const POLL: Duration = Duration::from_millis(200);
/// Wait before the next connect after netmond went away.
const RECONNECT: Duration = Duration::from_secs(5);
/// How long a notification stays: the time netmond waits for an answer.
const SHOW_MS: u128 = crate::ask::ASK_TIMEOUT.as_millis();
/// How long the notes about an answer stay.
const NOTE_MS: u32 = 4000;
/// How long a new-listener notification stays.
const LISTENER_MS: u32 = 10_000;
/// Destinations listed in the text of a notification.
const LISTED_DESTS: usize = 3;

/// The buttons, with the action names that `notify-send` prints.
const BUTTONS: [(&str, &str); 4] = [
    ("allow", "Allow"),
    ("deny", "Deny"),
    ("allow-always", "Allow always"),
    ("deny-always", "Deny always"),
];

/// Entry point of the `netmon-notify` binary.
pub fn run() -> anyhow::Result<()> {
    let args = NotifyArgs::parse();
    Command::new("notify-send")
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .context("run notify-send (install libnotify)")?;
    let mut first = true;
    loop {
        match Remote::connect(&args.socket) {
            Ok((remote, welcome)) => {
                eprintln!("netmon-notify: connected to {}", args.socket.display());
                let e = serve(remote, welcome.snapshot.questions, !args.no_listeners);
                eprintln!("netmon-notify: {e:#}");
            }
            // The first error is shown, later ones repeat it.
            Err(e) if first => eprintln!("netmon-notify: {e:#}; trying again every {} s", RECONNECT.as_secs()),
            Err(_) => {}
        }
        first = false;
        std::thread::sleep(RECONNECT);
    }
}

/// One shown question.
struct Shown {
    /// The notification id, when `notify-send` printed it.
    id: Arc<Mutex<Option<u32>>>,
}

/// Serves one connection to netmond. Returns when it ends.
fn serve(mut remote: Remote, questions: Vec<Prompt>, listeners: bool) -> anyhow::Error {
    let (tx, clicks) = mpsc::channel::<(u64, String)>();
    let mut shown: HashMap<u64, Shown> = HashMap::new();
    let mut questions = questions;
    loop {
        update(&mut shown, &questions, &tx);
        if let Err(e) = handle_clicks(&mut remote, &clicks, &questions) {
            close_all(&mut shown);
            return e;
        }
        std::thread::sleep(POLL);
        let msgs = match remote.poll() {
            Ok(m) => m,
            Err(e) => {
                close_all(&mut shown);
                return e;
            }
        };
        for m in msgs {
            match m {
                ToClient::Snapshot(s) => questions = s.questions,
                ToClient::Reply { req: Request::Answer { .. }, msg } => note("netmon", &msg),
                ToClient::Error(e) => note("netmon", &e),
                ToClient::Listener(l) if listeners => {
                    let (title, body) = listener_text(&l);
                    let _ = Command::new("notify-send")
                        .args(["-a", "netmon", "-u", "normal", "-t", &LISTENER_MS.to_string(), "--", &title, &body])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                _ => {}
            }
        }
    }
}

/// Shows the new questions, and closes the notifications of questions that
/// are gone.
fn update(shown: &mut HashMap<u64, Shown>, questions: &[Prompt], tx: &Sender<(u64, String)>) {
    for q in questions {
        shown.entry(q.id).or_insert_with(|| show(q, tx.clone()));
    }
    shown.retain(|qid, s| {
        let open = questions.iter().any(|q| q.id == *qid);
        if !open {
            close(s);
        }
        open
    });
}

fn close_all(shown: &mut HashMap<u64, Shown>) {
    for (_, s) in shown.drain() {
        close(&s);
    }
}

/// Replaces the notification with a short one. Then the server closes it,
/// and the waiting `notify-send` ends.
fn close(s: &Shown) {
    let id = *s.id.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(id) = id {
        let _ = Command::new("notify-send")
            .args(["-r", &id.to_string(), "-t", "1000", "-u", "low", "--", "netmon", "question closed"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Shows question `q` in a thread. A click comes back on `tx`.
fn show(q: &Prompt, tx: Sender<(u64, String)>) -> Shown {
    let id = Arc::new(Mutex::new(None));
    let qid = q.id;
    let mut cmd = Command::new("notify-send");
    cmd.args(["-p", "-w", "-a", "netmon", "-i", "network-wireless", "-u", "normal", "-t"]);
    cmd.arg(SHOW_MS.to_string());
    for (name, label) in BUTTONS {
        cmd.arg("-A").arg(format!("{name}={label}"));
    }
    cmd.arg("--").arg(summary(q)).arg(body(q));
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    let slot = id.clone();
    std::thread::spawn(move || {
        let Ok(mut child) = cmd.spawn() else { return };
        if let Some(out) = child.stdout.take() {
            let mut lines = BufReader::new(out).lines();
            if let Some(Ok(l)) = lines.next() {
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = l.trim().parse().ok();
            }
            if let Some(Ok(action)) = lines.next() {
                let _ = tx.send((qid, action.trim().to_string()));
            }
        }
        let _ = child.wait();
    });
    Shown { id }
}

/// Sends the answers for the clicked buttons.
fn handle_clicks(remote: &mut Remote, clicks: &Receiver<(u64, String)>, questions: &[Prompt]) -> anyhow::Result<()> {
    while let Ok((qid, action)) = clicks.try_recv() {
        let Some(q) = questions.iter().find(|q| q.id == qid) else { continue };
        for req in requests(q, &action) {
            remote.send(req)?;
        }
    }
    Ok(())
}

/// The requests for button `action` on question `q`. Allow and deny add a
/// rule until netmond stops, the "always" buttons a saved rule. The rule
/// covers the program, or the destination when the program is unknown.
pub(crate) fn requests(q: &Prompt, action: &str) -> Vec<Request> {
    let (allow, always) = match action {
        "allow" => (true, false),
        "deny" => (false, false),
        "allow-always" => (true, true),
        "deny-always" => (false, true),
        _ => return Vec::new(),
    };
    let Some(d) = q.selected_dest() else { return Vec::new() };
    let scope = if q.exe.is_empty() { Scope::Destination } else { Scope::Program };
    let mut out =
        vec![Request::Answer { question: q.id, dest: DestId::from(d), scope, answer: Answer::Rule { allow, always } }];
    if always {
        out.push(Request::SaveRules);
    }
    out
}

/// The title: who wants to connect. Titles are plain text, without markup.
pub(crate) fn summary(q: &Prompt) -> String {
    let comm: String = q.comm.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
    format!("{comm} wants to connect")
}

/// The text: the program and its destinations. Escaped, because the
/// server reads markup, and process names and hostnames are not trusted.
pub(crate) fn body(q: &Prompt) -> String {
    let who = if q.exe.is_empty() { format!("pid {} (program unknown)", q.pid) } else { q.exe.clone() };
    let mut lines = vec![format!("{who}, user {}", q.user)];
    for d in q.dests.iter().take(LISTED_DESTS) {
        let host = d.host.clone().unwrap_or_else(|| d.remote.to_string());
        lines.push(format!("{host} {} {}", proto_name(d.proto), d.port));
    }
    if q.dests.len() > LISTED_DESTS {
        lines.push(format!("and {} more", q.dests.len() - LISTED_DESTS));
    }
    if q.exe.is_empty() {
        lines.push("A rule covers this destination only.".into());
    }
    escape(&lines.join("\n"))
}

/// Title and text of a new-listener notification. The text is escaped,
/// the title is plain text.
pub(crate) fn listener_text(l: &crate::monitor::listen::NewListener) -> (String, String) {
    let comm: String = l.comm.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
    let title = format!("{comm} opened {} port {}", proto_name(l.proto), l.addr.port());
    let exe = if l.exe.is_empty() { "program unknown".to_string() } else { l.exe.clone() };
    (title, escape(&format!("on {}, pid {}\n{exe}", l.addr.ip(), l.pid)))
}

/// A short notification about an answer.
fn note(title: &str, msg: &str) {
    if msg.is_empty() {
        return;
    }
    let _ = Command::new("notify-send")
        .args(["-a", "netmon", "-u", "low", "-t", &NOTE_MS.to_string(), "--", title, &escape(msg)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Text with the markup characters escaped.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c if c.is_control() && c != '\n' => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Instant};

    use super::*;
    use crate::ask::Dest;

    fn prompt(exe: &str, dests: usize) -> Prompt {
        Prompt {
            id: 7,
            pid: 42,
            comm: "curl".into(),
            exe: exe.into(),
            user: "j".into(),
            dests: (0..dests)
                .map(|i| Dest {
                    remote: IpAddr::from([10, 0, 0, i as u8]),
                    port: 443,
                    proto: netmon_common::IPPROTO_TCP,
                    host: (i == 0).then(|| "<b>x</b>.example".to_string()),
                    conns: Vec::new(),
                })
                .collect(),
            since: Instant::now(),
            selected: 0,
            scope: Scope::Port,
        }
    }

    #[test]
    fn buttons_give_rule_answers() {
        let q = prompt("/usr/bin/curl", 1);
        let dest = DestId::from(&q.dests[0]);
        assert_eq!(
            requests(&q, "allow"),
            vec![Request::Answer { question: 7, dest, scope: Scope::Program, answer: Answer::Rule { allow: true, always: false } }]
        );
        assert_eq!(
            requests(&q, "deny-always"),
            vec![
                Request::Answer { question: 7, dest, scope: Scope::Program, answer: Answer::Rule { allow: false, always: true } },
                Request::SaveRules,
            ]
        );
        assert!(requests(&q, "something").is_empty());
        assert!(requests(&prompt("/usr/bin/curl", 0), "allow").is_empty());
    }

    #[test]
    fn listener_text_names_program_and_port() {
        let l = crate::monitor::listen::NewListener {
            proto: netmon_common::IPPROTO_TCP,
            addr: "0.0.0.0:8000".parse().unwrap(),
            pid: 9,
            comm: "py\x1b".into(),
            exe: "/usr/bin/<x>".into(),
        };
        assert_eq!(listener_text(&l), ("py? opened tcp port 8000".into(), "on 0.0.0.0, pid 9\n/usr/bin/&lt;x&gt;".into()));
    }

    #[test]
    fn unknown_program_gets_destination_scope() {
        let q = prompt("", 1);
        assert!(matches!(requests(&q, "deny")[0], Request::Answer { scope: Scope::Destination, .. }));
        assert!(body(&q).contains("pid 42 (program unknown)"));
    }

    #[test]
    fn body_lists_dests_and_escapes() {
        let b = body(&prompt("/usr/bin/curl", 5));
        assert_eq!(
            b,
            "/usr/bin/curl, user j\n&lt;b&gt;x&lt;/b&gt;.example tcp 443\n10.0.0.1 tcp 443\n10.0.0.2 tcp 443\nand 2 more"
        );
        assert_eq!(escape("a&b\x1b[1m"), "a&amp;b?[1m");
    }
}
