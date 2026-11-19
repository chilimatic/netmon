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

**Status: done** (steps 1–3: `7566557`, `391e5aa` and the listener
commit after them).

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

**Status (2026-11-19): done.** Steps 1 (`77aff1e`), 2 (`dba8c36`),
3 (`755c7c3`, process blocks by exe) and 4 (rtnetlink link events) done and
tested live.

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

**Decisions** (see `docs/REVIEW.md`): fail-open; lockout guard for
loopback, the SSH session and DNS to the local resolver.

**Steps.**
1. **Parser hardening.** VLAN tags (up to 2) without offload, bounded walk
   over IPv6 extension headers (hop-by-hop, routing, destination options,
   fragment, AH), non-first fragments have no ports. Shared parser, so the
   tests run on the host.
2. **IP and port blocks.** LPM tries for v4/v6 remotes and a port map,
   enforced in `connect4/6` and `sendmsg4/6` (EPERM) and in TC
   (`TC_ACT_SHOT`) for traffic without a local socket. Lockout guard in the
   kernel. Drop counters per rule. UI: `b` blocks the selected remote,
   Rules tab, `d` removes.
3. **Process blocks.** Block by exe path: a `sched_process_exec`
   tracepoint marks tgids whose exe is blocked, a `/proc` scan catches
   running processes, `connect`/`sendmsg` deny marked tgids.
4. **Interface events.** Netlink link notifications replace the 2-tick
   poll (REVIEW 19).

**Acceptance.**
- Block a `curl` connection: it fails, drop counter rises, unblock restores.
- Block `1.1.1.1/32`: `ping 1.1.1.1` fails, other hosts work.
- Block the exe `/usr/bin/curl`: new `curl` runs fail with
  `Operation not permitted`; other processes work.
- Packets with 3 IPv6 extension headers before TCP still match port rules.
- Quitting netmon removes every block.

## Phase 3 – Rule engine and rules file

**Status (2026-11-19): done.** All four steps tested live: rule table
(`3c2f6db`), rules file (`a771fa0`), direction and default deny
(`e686943`), save.

**Why.** Blocks should survive a restart, be editable as text, and combine
conditions ("curl may only reach port 443").

**Decisions (2026-11-19).**
- Full allow/deny engine: rules combine fields, first match wins, default
  action configurable (default `allow`).
- File: `/etc/netmon/rules.toml`, `--rules PATH` to override. netmon refuses a
  file (or parent directory) that is not owned by root or that group or
  others can write: whoever edits it controls a root firewall.
- Format: TOML.
- `process` is an absolute exe path only. `comm` is not accepted: every
  process can set its own comm.

**Design.**
- Kernel: an ordered rule table (`Array`, `MAX_RULES` = 256) replaces the
  LPM trie, port and exe maps. Each rule holds a field mask and the values:
  remote network (family, prefix, address), proto, port range, exe id,
  direction, action. `denied()` walks the table up to the rule count with
  `bpf_loop` and returns the first match. A plain bounded loop failed: the
  verifier checks every pass and hit its 1M instruction limit at rule 89.
  `bpf_loop` raises the minimum kernel from 5.11 to 5.17. The rule check,
  parsing, counting and capture are separate BPF functions, so the
  program, the rule check and the callback stay within the 512-byte stack;
  each BPF function takes at most 5 arguments. The same match
  function lives in `netmon-common`, so userspace (red rows) and tests use
  the kernel's exact logic.
- Two table halves and an active index: userspace writes the inactive half,
  then flips, so packets never see a half-written table.
- Per-slot hit counters (allow and deny). Userspace keeps the running total
  per rule across table rewrites.
- Exe rules: `EXE_IDS` (path -> exe id) and `TGID_EXE` (tgid -> exe id),
  kept by the exec/fork tracepoints and the `/proc` scan as in Phase 2.
- Direction is the side that opened the connection, not the packet
  direction. A `CONNS` LRU map (flow key -> direction, verdict) remembers
  flows: `connect`/`sendmsg` and the first egress packet open `out`, the
  first ingress packet opens `in`. Later packets reuse the stored verdict,
  so replies of allowed connections pass under default deny. An evicted
  entry is re-evaluated (an `in` reply may then be judged as new).
- The lockout guard (loopback, SSH session, resolver DNS) runs before the
  table and also wins over default deny.

**Steps.**
1. **Kernel rule table.** Ordered table, matcher in common, hit counters,
   exe ids. UI blocks become one-field deny rules at the top. Behaviour of
   Phase 2 unchanged (same live checks).
2. **Rules file.** Load and validate `/etc/netmon/rules.toml` at startup:
   ownership and mode check, TOML errors with line and reason, then netmon
   starts with no file rules. Rules tab shows action, fields, comment, hits.
   (Swapped with direction: allow rules can only come from the file, and
   default deny cannot be tested without them.)
3. **Direction and default action.** `CONNS` state map, `direction` field
   and top-level `default` in the file, header shows `DEFAULT DENY`.
4. **Save.** `s` in the Rules tab writes the current rules (UI and file) to
   the file, atomically (temp file + rename), mode 0644 root.

**Acceptance.**
- Rules load at startup and appear in the Rules tab.
- An invalid file is rejected with the line and the reason; netmon still
  starts with no rules.
- `allow exe /usr/bin/curl port 443` above `deny exe /usr/bin/curl`: curl to
  443 works, curl to 80 fails.
- Default deny with `allow direction=out`: outbound works, replies pass,
  an inbound connection to a local server fails, SSH stays up.
- Unit tests for parsing, matching order and compilation to map entries.

## Phase 4 – Hostnames: DNS answers and TLS SNI

**Status (2026-11-19): done.** DNS names (`cca2146`), TLS SNI (`ef66ce6`)
and two-segment ClientHellos tested live (curl, Chrome, Firefox).

**Why.** `151.101.1.91` says little; `reddit.com` says a lot. Also needed for
rules by hostname later.

**Design.**
- A second, always-on ring buffer `NAMES` (1 MiB) next to the capture ring.
  The kernel sends only candidate packets: the flow key, a kind and up to
  1500 bytes of L4 payload. `parse_packet` reports the payload offset.
- DNS: ingress UDP from port 53, on every interface (on `lo` this catches
  answers from a local stub resolver). Userspace parses the answers
  (compression pointers, hop and length limits, truncated data) and maps
  every A/AAAA address to the name that was asked. Cache of 4096 names,
  each kept 1 h after its last answer.
- TLS: egress TCP whose payload starts like a ClientHello (`16 03 xx`,
  handshake type 1). Userspace reads the SNI extension and stores it on the
  flow. SNI beats the DNS name: it is what the client asked this server for.
- UI: Remote column shows `name:port`; `h` toggles names and addresses
  (`n` already sorts by name). The detail line always shows the address.

**Steps.**
1. **DNS names.** Name ring, payload offset, DNS answer parser, name
   cache, Remote column, `h`.
2. **TLS SNI.** ClientHello check in the kernel, SNI parser, per-flow name.
3. **Two-segment ClientHello.** Browsers send ~1.8 KB ClientHellos
   (post-quantum key shares) and Chrome shuffles extensions, so SNI is often
   in the second segment. Name events copy up to 4 KiB (GSO super-packets
   hold the whole ClientHello); without GSO a `HELLO_PENDING` map sends the
   next segment and userspace joins both.

**Limits.**
- DNS over TLS/HTTPS (encrypted DNS) gives no names; SNI still does.
- QUIC (HTTP/3) encrypts its ClientHello: those flows show DNS names only.

**Acceptance.**
- `curl https://example.com` shows `example.com` as remote within one refresh.
- DNS-over-HTTPS clients still show SNI names.
- Decoder tests with captured DNS answers and ClientHello bytes, including
  truncated and malformed ones.

## Phase 5 – Ask on first connection

**Status (2026-11-19): done.** Steps 1 and 2 tested live (one commit).
Found live: questions from processes without a local socket (forwarded,
container, VM traffic) need port/destination rules without an exe.

**Why.** The OpenSnitch / Little Snitch workflow: unknown process connects,
user decides once.

**Decision (2026-11-19).** Drop the first packet and rely on TCP
retransmits (SYN retries after ~1, 3, 7, 15 s). The first UDP datagram is
lost; the app's own retry gets through. NFQUEUE may come later.

**Design.**
- New default action `ask` (`default = "ask"` in the rules file, or
  `--ask`). It applies to outbound TCP/UDP that no rule matches; unmatched
  inbound is denied. The lockout guard still wins.
- Kernel: `decide()` returns `ACTION_ASK`. TC drops the packet, caches
  `ask` in `CONNS` (retransmits are dropped without a new event) and sends
  an event (connection key, tgid) on a small `ASKS` ring. The socket hooks
  allow the call, so TC sees the SYN or datagram.
- Userspace answers by writing the connection's verdict into `CONNS`; the
  next retransmit passes or is dropped. A rule change re-decides asked
  connections and may ask again; userspace merges duplicates.
- Prompt in the TUI, one per program (exe; pid if the exe is unknown),
  listing its waiting destinations; more connections join it. Shows process, pid, exe, user,
  remote name and address, port. No answer in 30 s: deny once.
- `--once` mode has no prompt: asked connections stay dropped.

**Steps.**
1. **Ask once.** `ACTION_ASK`, `ASKS` ring, verdict write, `--ask` and
   `default = "ask"`, prompt with allow/deny once, timeout. Tested live:
   works, but one question per connection meant ~200 questions for a
   browser.
2. **Scoped answers.** One question per program listing its destinations.
   Scope program / port / destination; `a`/`d` temporary rules, `A`/`D`
   lasting rules, `o`/`x` once for the selected destination. New rules
   decide waiting connections in every question. "Once" answers stay with
   their connections through rule changes (`ConnState.answered`).
   `docs/rules.example.toml` pre-allows system services.

**Acceptance.**
- `curl https://example.com` in `--ask` mode blocks until allowed, then
  completes; "allow always" stores a rule and the next run is not asked.

## Phase 6 – Container and namespace awareness

**Status (2026-11-19): in progress.** Step 1 (container owners) done and
tested live. Step 2 next.

**Why.** Container traffic shows as `?` (or `unknown process` in ask mode)
and is counted several times (veth, bridge, uplink). Seen live: Docker with
17 bridges and veths on the development host.

**Facts.** A packet loses its socket when it crosses into the host's
network namespace, so TC on the host never sees a cookie for container
traffic. The cgroup hooks do see container processes, but connect runs
before the local port exists. `/proc/<pid>/net/*` shows the socket table
of that process's namespace; `/proc/*/fd` already covers container
processes, so socket inodes resolve to their owners as on the host.

**Design.**
- Namespaces: group `/proc/*/ns/net` by inode, one pid per namespace,
  skip netmon's own. Container name from the pid's cgroup: Docker
  (`docker-<id>.scope`, name from `/var/lib/docker/containers/<id>/
  config.v2.json`), Podman (`libpod-<id>.scope`, short id), else
  `netns:<inode>`.
- Per namespace, read `/proc/<pid>/net/{tcp,udp}{,6}` into a table, in a
  background thread: measured 150-250 ms for 32 namespaces (each UDP read
  walks the kernel's whole UDP hash table). Read only while a flow lacks a
  good owner, at most every 3 s, and when an ask event has no process.
  Flows with no host owner are matched:
  - veth and bridge interfaces see the container as the remote end:
    exact lookup with local and remote swapped;
  - the uplink after masquerade: remote address, remote port and local
    port (masquerade keeps the port unless it clashes).
- Owner source `container`; Process column `container:<name>/<comm>`.
  Ask questions for traffic without a socket name the container.
- Totals count physical interfaces only (`/sys/class/net/<if>/device`);
  `v` shows or hides veth and bridge rows (hidden by default).

**Steps.**
1. **Container owners.** Namespace scan, per-namespace socket tables,
   matching, container names, ask questions.
2. **Count once.** Physical-only totals, `v` toggle.

**Limits.** Rules cannot name a container yet: the kernel sees no process
for its traffic on the host. Rules by address and port still apply.

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
