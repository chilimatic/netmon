# Second review of netmon at 2aa5321

Three independent read-only reviews (architect, critic, security reviewer)
on 2026-11-19, after Phases 1 to 7 and the CPU work. The findings are
merged here and duplicates are removed. The source of each finding is
noted as **A** (architect), **C** (critic) or **S** (security). Items with
"spot-checked" were read again in the code before this file was written.

The first review is `docs/REVIEW.md`. None of its findings came back,
except #7 (local and forwarded traffic), which is still open for the
verdict (see F1).

Verdict of all three: the monitor, the daemon split, the capture and the
parsers that run as root are in good shape. The firewall is not ready to
trust on a server or a container host. The blockers are bypasses of the
verdict (B1 to B4), ask-mode verdicts that never end (K1, K2) and the
restart window (L1).

Status column: `open` for all items at the time of writing.

## Firewall bypasses and wrong verdicts

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| B1 | High | A remote host passes every inbound rule with UDP source port 67, 68, 546 or 547 (DHCP exemption matches the remote port in both directions), with TCP/UDP source port 0 (port-0 exemption is not limited to fragments), or with more than 6 IPv6 extension headers (the walk returns proto 60, and non-TCP/UDP is allowed). Spot-checked: `is_dhcp` and `default_action`. | `netmon-common/src/lib.rs:163` (`is_dhcp`), `:491-535`; `netmon-ebpf/src/main.rs:207`, `:239-241` | S | fixed (step 1) |
| B2 | High | Rules made from ask answers have no direction. `allow udp port 53` at port scope also lets any host with source port 53 reach every local UDP port. An exe answer also opens that exe's listeners. Spot-checked. | `netmon/src/ask.rs:109-123`; `netmon-common/src/lib.rs:208` | C | fixed (step 1) |
| B3 | High | `TGID_EXE` (8192 entries, not LRU) fills with thread ids: the fork tracepoint fires for each thread and nothing removes entries of exited tasks. A full map makes new processes unmarked: deny-exe rules stop matching, allow-exe rules stop matching. The failed insert is not reported. Spot-checked. | `netmon-ebpf/src/main.rs:765-781`; `netmon-common/src/lib.rs:61`; `netmon/src/probe.rs:683-689` | A, S | open |
| B4 | High | Exe identity is the `execve` filename string. `cd /usr/bin && ./curl`, `../`, symlinks and `execveat` stay unmarked until the `/proc` scan (every 10 ticks), and connections in that window are cached with `exe_known=1`. A copy of the binary is never caught. `LD_PRELOAD`, ptrace or a bind mount in a user namespace run own code under an allowed path. | `netmon-ebpf/src/main.rs:738-760` | S | open; document that exe rules do not stop a same-uid attacker |
| F1 | High | Container and VM traffic is decided in the wrong direction. On TC ingress of a veth or bridge, a container's outbound SYN gets `DIR_IN` with the destination taken as local. In deny or ask mode it is denied without a question, and `direction = "out"` rules and destination rules never match there. Needs a netns + veth test: the live container questions may have come from egress with tgid 0. | `netmon-common/src/lib.rs:626-631`; `netmon-ebpf/src/main.rs:247`, `:265`, `:462` | A | open (REVIEW #7) |
| G1 | High | No SSH lockout guard under systemd. `ssh_connection()` walks parent processes and finds none for a daemon started by PID 1. With `docs/rules.example.toml` (`default = "ask"`, no inbound rule for sshd) a remote admin is locked out. The README claims the guard applies to netmond. | `netmon/src/monitor.rs:792-810` | A, S | fixed (step 1) |
| G2 | Medium | The lockout guard is too wide: `GuardKey` has no protocol and no local port, so packets from the resolver address with port 53 reach every local port. A LAN host that spoofs the resolver passes all inbound rules. The guard is also read once at start: a new resolver after a network change is not guarded. | `netmon-ebpf/src/main.rs:220`; `netmon/src/monitor.rs:191-192` | S, A | open |

## Ask mode and connection state

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| K1 | High | Verdicts written with `set_verdict` (once, timeout, too many questions) set `answered=1`, and the kernel returns them before the generation check. They never end until LRU eviction. "Allow once" outlives a later deny rule or `b`. A timeout deny of a fixed-port UDP flow (WireGuard, NTP) survives a later allow. `ConnKey` has no local address and no process, so a later socket on the same port and remote inherits the verdict. Spot-checked. | `netmon-ebpf/src/main.rs:273`, `:323`; `netmon/src/probe.rs:566-569`; `netmon/src/monitor.rs:527-535` | C, A, S | fixed (step 2) |
| K2 | Medium | An ASK state can be orphaned: when the ASKS ring is full the event is lost but ASK is still cached, and retransmits send no new event. Connections over 256 per destination are dropped in userspace but reported as `Joined`. Such connections are dropped with no question and no timeout. | `netmon-ebpf/src/main.rs:138`, `:284`; `netmon/src/ask.rs:180` | A | fixed (step 2) |
| K3 | Medium | A userspace rule matches but the kernel did not (exe not marked yet): `poll_asks` skips the question, and the kernel cached ASK with `exe_known=1`, so it is not decided again after the pid is marked. The connection hangs silently. | `netmon/src/monitor.rs:524-526`; `netmon-ebpf/src/main.rs:283` | C | fixed (step 2) |
| K4 | Medium | Asks of different containers merge into one question with the first container's name (pid 0 is the same for all before the tables arrive). | `netmon/src/ask.rs:95`; `netmon/src/monitor.rs:539-545` | C | fixed (step 2) |
| K5 | Medium | A remote host can evict `CONNS` entries (65 536, LRU) with spoofed new flows: every inbound 5-tuple is inserted, also when denied. An evicted outbound connection is decided again as inbound on its next reply and denied. | `netmon-ebpf/src/main.rs:276`, `:282-284` | A, S | open |
| K6 | Medium | `SOCK_OWNER` (16 384) and `LISTENERS` (4096) are LRU maps but feed the verdict. A local process that opens many sockets or binds many ports evicts other owners. After a rule change those connections are decided with tgid 0, so exe rules no longer apply to them. | `netmon-ebpf/src/main.rs:63-70` | A, S | open |
| K7 | Medium | Names in the ask prompt come from any UDP packet with source port 53, also dropped and unsolicited ones. A remote host can make an address show as a trusted name and lead the user to allow it. | `netmon-ebpf/src/main.rs:456`; `netmon/src/monitor.rs:583`, `:662` | S | open |
| K8 | Low | Back-to-back rule updates can rewrite the half a CPU still walks. `CFG_DEFAULT` is written before `CFG_ACTIVE`. One packet can see a mixed table. | `netmon/src/probe.rs:629-635` | A | open |
| K9 | Low | Suspected race: the kernel reads an unanswered entry, `set_verdict` writes the answer, the kernel's later insert overwrites it, and the user gets the question again. | `netmon-ebpf/src/main.rs:282-284` | A | suspected |

## Lifecycle: restart, crash, rules file

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| L1 | High | Restart (also the automatic one after a crash) removes the old pins before the new programs attach and before the rules load: a fail-open window. After it, `SOCK_OWNER` is empty, so established connections are decided again with tgid 0 and possibly as inbound: in deny or ask mode long-lived connections of allowed programs are dropped or asked. "Rules survive a crash" holds only until the restart 2 s later. | `netmon/src/probe.rs:108-120`; `netmon/src/monitor.rs:210` | A, S | open |
| L2 | High | A rules file that fails part-way leaves its first rules and its default in memory: `change_rules` does not restore the old rules when the edit fails. The status says "no file rules loaded", and the next rule change writes the half-loaded rules and the default to the kernel. `rulefile::parse` checks neither duplicates nor the 256 limit. | `netmon/src/monitor.rs:721-723`, `:756-765`; `netmon/src/rulefile.rs:120-135` | C | fixed (step 1) |
| L3 | Medium | Any error in the rules file starts the daemon with no file rules and default allow. A member of group `netmon` can save a rule the file parser refuses (`Match::check` does not reject host bits, the file parser does) and so turn `default = "deny"` into allow at the next start. | `netmon/src/monitor.rs:740-770`; `netmon/src/rules.rs:125-150`; `netmon/src/rulefile.rs:186-205` | S | open |
| L4 | High (kernel < 6.6) | Before tcx, TC filters are netlink filters: they stay after a crash, the restart adds another one, and `rm -r /sys/fs/bpf/netmon` does not remove them. The old filter keeps its frozen rules and nobody drains its ASKS ring. | `netmon/src/probe.rs:253-256` | A | open |
| L5 | Low | After a crash, new interfaces (VPN, veth) get no TC programs until the restart. An ifindex removed and reused between two scans is never attached. | `netmon/src/probe.rs:473` | A | open |
| L6 | Low | `SIGHUP` is a clean stop with exit code 0: the rules end and `Restart=on-failure` does not restart. | `netmon/src/daemon.rs:100` | C | open |

## Daemon and socket

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| D1 | Medium | Memory: each snapshot is the full collector as JSON (MBs with 30 000 flows), and each client can queue 256 lines. A client stopped with Ctrl-Z holds GBs. The request channel is unbounded and each request makes a snapshot, so a group member can grow the root daemon's memory without limit. | `netmon/src/daemon.rs:53`, `:104`; `netmon/src/engine.rs:63-82` | A, S | open |
| D2 | Medium | `write_lines` has no write timeout: a client that never reads blocks its writer thread and keeps its slot. 16 such clients lock out every UI, root included. | `netmon/src/daemon.rs:284-290` | S | open |
| D3 | Medium | Group `netmon` can do more than the README says: remove any rule and save, capture any interface (also `lo`) and any process of any user. It is a host-wide sniffer plus firewall admin. | README; `netmon/src/monitor.rs` (`request`) | S | open (document) |
| D4 | Low | With `--socket` in a directory an attacker can write, `chown`/`chmod` after `bind` follow a swapped symlink. Use `RuntimeDirectory=netmon` (0750 root:netmon). | `netmon/src/daemon.rs:204-205` | S | open |
| D5 | Low | The second peer check reads `/proc/<pid>/status` (pid reuse race). It adds nothing beyond the 0660 socket mode. Use `SO_PEERGROUPS`. | `netmon/src/daemon.rs` (`allowed`) | S | open |
| D6 | Low | `prepare_pins` creates the pin directory without a mode or owner check. | `netmon/src/probe.rs:108-120` | S | open |
| D7 | Low | Exe strings from a client are not checked for control characters; they show in other admins' Rules tab. | `netmon/src/rules.rs` (`Match::check`) | S | open |
| D8 | Medium | systemd hardening is thin for a root daemon that parses network data: no `CapabilityBoundingSet`, `ProtectSystem=full` not `strict`, no `RestrictAddressFamilies`, `SystemCallFilter`, `MemoryMax`, `TasksMax`. Each directive must be tested with the eBPF load. | `dist/netmond.service` | S | open |

## UI and README

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| U1 | Medium | An open question takes `x`, `d`, arrows and `j`/`k` in every tab: in Capture `x` denies instead of stopping, in Rules `d` makes a deny rule. The key line still shows `x stop` and `d remove rule`. No way to put a question aside. | `netmon/src/app.rs:253-268`; `netmon/src/ui.rs:100-102` | C | fixed (step 2) |
| U2 | Medium | A capture that fails to start leaves the old capture marked running; a process capture turns itself on again at the next tick. | `netmon/src/monitor.rs:405-420` | C | open |
| U3 | Medium | README says UI blocks are temporary and show `tmp`. In the code, `b`/`B` blocks are not temporary (no `tmp`, `s` saves them). Only `a`/`d` answers are temporary and can never be saved. | `netmon/src/rules.rs:238`; README | C | fixed (step 1) |
| U4 | Low | README errors: "within 10 s" is 10 ticks; "more headers count with port 0" is proto 60 (B1); the guard "applies to netmond" (G1). `rules.rs` module comment still says a crash removes every rule. | README; `netmon/src/rules.rs:1-3`; `netmon/src/monitor.rs:108` | C, S | fixed (step 1) |
| U5 | Low | Only the first error of an engine step is shown. `x` with no capture reports "capture stopped". `--interval-ms`/`--expire-secs` are ignored silently with a daemon. A process row is red if any deny rule names its exe, also a port-only one. | `netmon/src/engine.rs:75`; `netmon/src/client.rs:172`; `netmon/src/tui.rs:110`; `netmon/src/rules.rs:329-331` | C | open |
| U6 | Low | `monitor.rs` (1477 lines) holds owners, rules, asks, hostnames, capture and containers. | `netmon/src/monitor.rs` | A | open |

## Test gaps

- The fake kernel ignores `answered` and the generation, so no test can find K1. `Fake::rule_hits` never resets, unlike the real probe, so one test checks numbers the kernel never gives.
- No test for: a rules file with a duplicate or over 256 rules (L2), `--ask` with the file default, the direction of answer rules (B2), the start-capture error path (U2).
- No tests in `client.rs`, `engine.rs` (beyond one), `tui.rs`; no test of `serve` with two clients.
- No end-to-end eBPF test: needed for F1 (netns + veth), L1 (`kill -9` and restart) and B3 (thread-heavy process against an exe rule).
- `rules_file_owned_by_a_user_is_refused` fails under `sudo cargo test`.
- `cargo audit` was not run (no network).

## Suggested order

1. Quick fixes with large effect: B2 (direction out on answer rules), L2 (restore rules on error, check the file fully), B1 (DHCP by both ports and direction, port 0 only for real fragments, unparsed IPv6 by the TCP/UDP default), G1 (guard sshd's listening port in daemon mode or ship an inbound allow for it), U4 and U3 (README and comments).
2. Ask-mode state: K1 (answered verdicts end with the generation), K2, K3, K4, U1.
3. Kernel maps: B3 (exit hook, no thread ids), K5, K6.
4. Restart: L1 (attach and write rules before removing old pins, or replace links with `bpf_link_update`; fill `SOCK_OWNER` at start), L3, L4.
5. Container direction F1 with a netns + veth test.
6. Daemon limits D1, D2, then hardening D8 and the rest.
7. B4 needs inode-based exe identity (kernel side needs BTF or an LSM hook). Until then the README says plainly that exe rules do not stop an attacker with the same uid.
