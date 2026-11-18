# netmon roadmap

netmon is a monitor today: it counts, attributes and captures traffic. The
goal is a host firewall with the same UI: see a connection, block it, keep the
decision as a rule, and get asked when an unknown process connects.

Each phase is one or more small commits. A phase is done when its acceptance
checks pass and it is committed (signed). Later phases depend on earlier ones;
the order below is the build order.

| Phase | Feature | Depends on |
|------:|---------|------------|
| 0 | Fixes from the architect / security / critic review (`docs/REVIEW.md`) | – |
| 1 | Kernel-side process identity (cgroup hooks, socket cookies) | 0 |
| 2 | Block from the UI | 1 |
| 3 | Rules file | 2 |
| 4 | Hostnames: DNS answers + TLS SNI | 0 |
| 5 | Ask on first connection | 1, 2, 3 |
| 6 | Container / network namespace awareness | 1 |
| 7 | Privileged daemon + unprivileged TUI | 3 |
| 8 | Extras: GeoIP/ASN, alerts, capture filters, follow stream, history | 4 |

---

## Phase 0 – Review fixes

**Status: done** (commits `bd83a87`, `bad5eb7`, `974aa9e`, `b1190b2`,
`40abd38` and the test commit after them).

Fix every finding marked `P0` in `docs/REVIEW.md`, in small commits:

1. **Crash and safety:** decoder panic (1), tcx return value (2), pcap save
   hardening (11), escape sanitizing (23).
2. **Correctness:** owner fallback needs an address match (3), pause (4),
   duplicate snapshot keys (14), monotonic interface totals (15), `lo` double
   capture (17), racy first insert (26), expiry with clamped interval (28).
3. **Robustness:** clsact on kernels < 6.6 (5), flow map sized from CPU count
   (13), capture key consistency (24), `L3_OFFSET` cleanup (25), per-capture
   drop counter (27), stop drains into the capture (29).
4. **UX and performance:** selection follows the row's key (18), inode→owner
   cache so `/proc/*/fd` is scanned only for unknown inodes (16).
5. **Docs:** minimum kernel, capability set and binary permissions, owner
   limits (12, 30).
6. **Tests:** decoder fuzz test, main-loop tests for pause and capture
   start/stop, parser tests for VLAN and IPv6 extension headers.

## Phase 1 – Kernel-side process identity

**Why.** Rules by process and the first-connection prompt need the owner of a
flow before its first packet leaves. `/proc` polling is late (up to 1 s),
misses short-lived sockets, and can be fooled by binding a port (REVIEW 3, 6,
10).

**Design** (changed after review: cgroup hooks instead of kprobes, because
aya has no CO-RE field access for Rust programs and cgroup context fields are
stable kernel API):
- Attach `cgroup/sock_create`, `cgroup/connect4`, `cgroup/connect6`,
  `cgroup/sendmsg4`, `cgroup/sendmsg6` and `cgroup/post_bind4/6` to the root
  cgroup (`/sys/fs/cgroup`).
- Key everything by **socket cookie** (`bpf_get_socket_cookie`). Map
  `SOCK_OWNER: cookie -> {tgid, uid, cgroup_id, comm}` (LRU, monitoring only).
  Connect/sendmsg add the remote address.
- TC egress joins packets to owners with `bpf_get_socket_cookie(skb)`;
  ingress joins by 5-tuple through a `TUPLE_COOKIE` map filled at connect and
  bind time.
- Userspace turns `tgid` into **exe path** and **systemd unit / cgroup path**
  once per new socket (event via ring buffer). Rules (Phase 3) use these, never
  `comm` or a pid.
- `/proc` scanning stays only as a fallback for sockets that existed before
  netmon started.

**Steps.**
1. **Cookie owners.** `cgroup/sock_create`, `connect4/6` and `sendmsg4/6`
   write `cookie -> {tgid, uid, cgroup_id, comm}` into `SOCK_OWNER` (LRU,
   16 384 entries). The hooks always return 1 (allow) and only observe. TC
   egress stores the skb's socket cookie in the flow counters. Userspace
   prefers the kernel owner and falls back to `/proc`. If a cgroup hook does
   not load or attach (old kernel, no cgroup v2), netmon warns and runs as
   before.
2. **Exe path and cgroup.** Userspace resolves `tgid` to the exe path
   (`/proc/<pid>/exe`) and the cgroup path (`/proc/<pid>/cgroup`) once per
   process and caches it. Processes tab shows the exe; a detail line shows
   uid and systemd unit.
3. **Servers and receive-only flows.** Accepted sockets have no connect
   hook: `post_bind4/6` records listener owners by port, and a flow whose
   first packets are ingress gets the owner as soon as one egress packet
   carries the cookie.

**Acceptance.**
- `dig example.com` and `curl https://…` show their process on the first
  refresh, including DNS over `sdwan0`.
- Container DNS is no longer attributed to `systemd-resolved`.
- A process that renames itself with `prctl(PR_SET_NAME)` still shows its exe
  path.

## Phase 2 – Block from the UI

**Why.** The first firewall feature.

**Design.**
- Verdict maps, never LRU, explicit `max_entries`: `BLOCK_REMOTE` (LPM trie,
  v4 and v6), `BLOCK_PORT` (proto, port), `BLOCK_EXE` / `BLOCK_CGROUP`
  (cgroup id or exe hash), plus a `POLICY` map with the default verdict and
  the lockout guard.
- Per-process and per-remote blocks are enforced in `cgroup/connect4/6` and
  `cgroup/sendmsg4/6` (return 0: the app gets `EPERM`). IP and port blocks are
  also enforced in TC (`TC_ACT_SHOT`) for traffic without a local socket.
  Pass stays `TC_ACT_UNSPEC`.
- Parser hardening first: bounded walk over IPv6 extension headers, VLAN
  tags, fragments get the default verdict (REVIEW 9).
- Netlink link events replace the 2-tick interface poll (REVIEW 19).
- UI: `b` on a connection, process or remote IP toggles a block. Blocked rows
  are red with a drop count. A **Rules** tab lists blocks; `d` removes one.
- Safety: loopback and the SSH session netmon runs in are never blocked
  (lockout guard). Without the daemon (Phase 7) blocks end when netmon exits.

**Acceptance.**
- Block a `curl` connection: it fails, drop counter rises, unblock restores.
- Block `1.1.1.1/32`: `ping 1.1.1.1` fails, other hosts work.
- Block the exe `/usr/bin/curl`: new `curl` runs fail with
  `Operation not permitted`; other processes work.
- Packets with 3 IPv6 extension headers before TCP still match port rules.
- Quitting netmon removes every block.

## Phase 3 – Rules file

**Why.** Blocks should survive a restart and be editable as text.

**Design.**
- `~/.config/netmon/rules.toml` (under sudo: the invoking user's config dir,
  read and validated before use; refuse files writable by other users).
- Rule fields: `action` (`allow` | `deny`), optional `process` (comm or exe
  path), `remote` (IP or CIDR), `port`, `proto`, `direction`, `comment`.
  First match wins; default action configurable, default `allow`.
- Rules compile into the Phase 2 maps. Exe-path rules resolve to tgids at
  connect time through `SOCK_OWNER`.
- `s` in the Rules tab saves the current blocks to the file.

**Acceptance.**
- Rules load at startup and appear in the Rules tab.
- An invalid file is rejected with the line and the reason; netmon still
  starts with no rules.
- Unit tests for parsing, matching order and compilation to map entries.

## Phase 4 – Hostnames: DNS answers and TLS SNI

**Why.** `151.101.1.91` says little; `reddit.com` says a lot. Also needed for
rules by hostname later.

**Design.**
- Always-on lightweight capture of DNS responses (UDP/TCP port 53 ingress)
  into a small ring buffer. Decoder parses A/AAAA/CNAME answers into an
  `ip -> name` cache with TTL.
- TLS: on TCP egress packets with payload, if the first payload bytes are a
  ClientHello, parse the SNI extension in userspace and attach it to the flow.
- UI: Remote column shows the name, `n` toggles names/addresses.

**Acceptance.**
- `curl https://example.com` shows `example.com` as remote within one refresh.
- DNS-over-HTTPS clients still show SNI names.
- Decoder tests with captured DNS answers and ClientHello bytes, including
  truncated and malformed ones.

## Phase 5 – Ask on first connection

> **Decision needed before this phase** (see `docs/REVIEW.md`): how a
> connection waits for the answer – deny in `cgroup/connect` and let the user
> retry, drop the SYN and rely on TCP retransmits, or NFQUEUE. The design below
> assumes the SYN-drop variant and will be updated.

**Why.** The OpenSnitch / Little Snitch workflow: unknown process connects,
user decides once.

**Design.**
- Mode `--ask`: a process with no matching rule gets its first outgoing packet
  (TCP SYN / first UDP datagram) dropped and an event sent to userspace.
- The UI shows a prompt: process, exe path, remote host/IP, port, with
  *allow once*, *allow always*, *deny once*, *deny always*. "Always" writes a
  rule (Phase 3). Retransmits (TCP retries after ~1 s) pass once allowed.
- Timeout with no answer applies the default action.
- System processes (systemd-resolved, NetworkManager, sshd) can be
  pre-allowed in the default rules file.

**Acceptance.**
- `curl https://example.com` in `--ask` mode blocks until allowed, then
  completes; "allow always" stores a rule and the next run is not asked.

## Phase 6 – Container and namespace awareness

**Why.** Container traffic shows as `?` and is counted twice (veth and
bridge).

**Design.**
- Map veth peers to network namespaces (`/proc/<pid>/ns/net`, `ip link`
  peer index) and namespaces to container names (Docker/Podman via
  `/proc/<pid>/cgroup`).
- Read `/proc/<pid>/net/{tcp,udp}` per namespace for owners.
- Option to show only "uplink" interfaces in totals, so bridged traffic is
  counted once.

**Acceptance.**
- Rows for container traffic show `container:<name>/<process>`.
- Header total matches `/proc/net/dev` of the uplink within a few percent.

## Phase 7 – Privileged daemon and unprivileged TUI

**Why.** Rules must hold when the UI is closed, and the UI should not run as
root.

**Design.**
- `netmond` (systemd service, root or minimal capabilities) owns the eBPF
  programs, maps and rules. It pins programs and maps under `/sys/fs/bpf`.
- `netmon` connects over a Unix socket (`/run/netmon.sock`, group `netmon`),
  receives snapshots and capture streams, sends rule changes. The protocol is
  versioned and every request is validated by the daemon.
- Prompts (Phase 5) go to every connected TUI; with no TUI, the default action
  applies.

**Acceptance.**
- Rules apply at boot with no user logged in.
- TUI runs without sudo for a member of group `netmon`.
- Killing the TUI leaves blocks active; stopping the service removes them.

## Phase 8 – Extras

Small, independent features after the firewall core:

- **GeoIP / ASN** column from an offline DB-IP or MaxMind file.
- **Alerts**: highlight a process above a rate, or contacting a new country or
  port.
- **Capture filters**: `tcp port 443`, `dns`, `host 1.1.1.1` in the Capture
  tab.
- **Follow stream**: rebuild one TCP stream and show its plaintext.
- **History**: per-process daily totals in SQLite.

---

## Rules for every phase

- Tests first for parsers and pure logic; render tests for new UI.
- `AYA_BUILD_SKIP=1 cargo test`, `cargo clippy --all-targets` clean, and a
  full `cargo build --release` with the eBPF object before each commit.
- Live check as root for kernel changes (the verifier only runs on load).
- One signed commit per finished step, conventional commit messages.
