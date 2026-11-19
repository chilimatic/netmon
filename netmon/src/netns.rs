//! Network namespaces other than netmon's own (containers), with a name
//! for each: Docker container name, Podman id, or the namespace inode.

use std::{collections::BTreeMap, fs};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Netns {
    pub inode: u64,
    /// One process in the namespace (the lowest pid), whose
    /// /proc/<pid>/net/* shows the namespace's sockets.
    pub pid: u32,
    /// Every process in the namespace: only these can own its sockets.
    pub pids: Vec<u32>,
    pub name: String,
}

/// Inode of a `net:[4026531840]` namespace link.
fn ns_inode(link: &str) -> Option<u64> {
    link.strip_prefix("net:[")?.strip_suffix(']')?.parse().ok()
}

fn netns_of(pid: &str) -> Option<u64> {
    ns_inode(&fs::read_link(format!("/proc/{pid}/ns/net")).ok()?.to_string_lossy())
}

/// Every network namespace with a process in it, except netmon's own.
pub fn scan() -> Vec<Netns> {
    let Some(own) = netns_of("self") else { return Vec::new() };
    let Ok(dir) = fs::read_dir("/proc") else { return Vec::new() };
    let mut members: BTreeMap<u64, Vec<u32>> = BTreeMap::new();
    for e in dir.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        if let Some(ino) = netns_of(&pid.to_string())
            && ino != own
        {
            members.entry(ino).or_default().push(pid);
        }
    }
    members
        .into_iter()
        .map(|(inode, mut pids)| {
            pids.sort_unstable();
            let pid = pids[0];
            let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
            let name = container_name(&cgroup, docker_name).unwrap_or_else(|| format!("netns:{inode}"));
            Netns { inode, pid, pids, name }
        })
        .collect()
}

/// Container of a process from its cgroup file: Docker or Podman.
/// `docker` turns a Docker id into a name.
fn container_name(cgroup: &str, docker: impl Fn(&str) -> Option<String>) -> Option<String> {
    let path = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    for part in path.split('/').rev() {
        // systemd driver: docker-<id>.scope; cgroupfs driver: /docker/<id>.
        if let Some(id) = part.strip_prefix("docker-").and_then(|p| p.strip_suffix(".scope")) {
            return Some(docker(id).unwrap_or_else(|| short(id)));
        }
        if let Some(id) = part.strip_prefix("libpod-").and_then(|p| p.strip_suffix(".scope")) {
            return Some(format!("podman-{}", short(id)));
        }
    }
    let mut parts = path.split('/').filter(|p| !p.is_empty());
    if parts.next() == Some("docker")
        && let Some(id) = parts.next()
    {
        return Some(docker(id).unwrap_or_else(|| short(id)));
    }
    None
}

fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

/// Docker's name for a container id, from its config file.
fn docker_name(id: &str) -> Option<String> {
    if !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let cfg = fs::read_to_string(format!("/var/lib/docker/containers/{id}/config.v2.json")).ok()?;
    json_name(&cfg)
}

/// The top-level `"Name":"/web"` of a Docker config, without the slash.
/// A full JSON parser is not needed for one string field; the value is
/// sanitized because it is shown in the terminal.
fn json_name(cfg: &str) -> Option<String> {
    let rest = &cfg[cfg.find("\"Name\":\"")? + 8..];
    let name = &rest[..rest.find('"')?];
    let name = crate::text::sanitize(name.trim_start_matches('/'));
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_names_from_cgroups() {
        let named = |id: &str| (id == "abc123").then(|| "web".to_string());
        let id = "abc123";
        assert_eq!(container_name(&format!("0::/system.slice/docker-{id}.scope\n"), named).as_deref(), Some("web"));
        let long = "f".repeat(64);
        assert_eq!(
            container_name(&format!("0::/system.slice/docker-{long}.scope"), named).as_deref(),
            Some("ffffffffffff"),
            "unknown id: short id"
        );
        assert_eq!(container_name(&format!("0::/docker/{id}"), named).as_deref(), Some("web"), "cgroupfs driver");
        assert_eq!(
            container_name(&format!("0::/machine.slice/libpod-{long}.scope/container"), named).as_deref(),
            Some("podman-ffffffffffff")
        );
        assert_eq!(container_name("0::/user.slice/user-1000.slice/session-2.scope", named), None);
        assert_eq!(container_name("", named), None);
    }

    #[test]
    fn docker_config_name() {
        let cfg = r#"{"StreamConfig":{},"State":{"Running":true},"ID":"abc","Name":"/web-1","Driver":"overlay2"}"#;
        assert_eq!(json_name(cfg).as_deref(), Some("web-1"));
        assert_eq!(json_name(r#"{"Name":"/\u001b[31m"}"#).as_deref().map(|n| n.contains('\u{1b}')), Some(false));
        assert_eq!(json_name("{}"), None);
        assert_eq!(docker_name("../../etc/passwd"), None, "ids are hex only");
    }

    #[test]
    fn namespace_links() {
        assert_eq!(ns_inode("net:[4026531840]"), Some(4026531840));
        assert_eq!(ns_inode("mnt:[1]"), None);
        // Runs unprivileged: own namespace is skipped, the rest may be
        // unreadable; it must not panic.
        let _ = scan();
    }
}

