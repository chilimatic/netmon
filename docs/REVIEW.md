# Review of netmon at 0bf7ed8

Three independent read-only reviews (architect, security reviewer, critic) on
2026-11-18. Findings are merged and deduplicated here; the source of each is
noted as **A** (architect), **S** (security), **C** (critic).

Verdict of all three: works as a monitor, **not ready for firewall features**.
The blockers are owner identity (guessed after the fact from `/proc`), the
flow model (no local-vs-forwarded distinction), the TC return value, and the
lifetime of eBPF state.

Status column: `P0` = fixed in Phase 0, `Pn` = fixed in roadmap phase n,
`doc` = documented as a limit.

## Critical / High

| # | Finding | Where | Src | Status |
|---|---------|-------|-----|--------|
| 1 | One malformed IPv4 packet (IHL larger than the captured L3 data) panics the decoder and kills netmon during a capture. Reproduced; 5 599 of 200 000 random frames panicked. | `netmon/src/decode.rs:119` | S | P0 |
| 2 | Programs return `TC_ACT_OK`. Under tcx (kernel ≥ 6.6) that is `TCX_PASS`, which ends the chain: tcx programs attached after netmon (Cilium, other monitors) never run. Pass must be `TC_ACT_UNSPEC` (`TCX_NEXT`). | `netmon-ebpf/src/main.rs` (`tc_egress`, `tc_ingress`) | A | P0 |
| 3 | Owner fallback by `(proto, local port)` ignores the address. With "ingress dst = local", container DNS to `8.8.8.8:53` seen on docker0/veth is attributed to `systemd-resolved` (`127.0.0.53:53`); a process capture of it then includes the container's packets. Spoofable by binding a port. | `netmon/src/procmap.rs` (`build`, `lookup`), `netmon-common/src/lib.rs` (`FlowKey::from_packet`) | C, S | P0 (address match), P6 (forwarded model) |
| 4 | Pause resets the time base but not the counters: after a 60 s pause rates and the graph show ~60×. | `netmon/src/main.rs` (pause branch) | C | P0 |
| 5 | Kernels < 6.6 need a `clsact` qdisc; netmon never adds it, so attach fails on Ubuntu 22.04, Debian 12, RHEL 9. | `netmon/src/probe.rs` (`attach`) | C | P0 |
| 6 | Owners come from a 1 s `/proc` poll after the packets. A verdict must be made at the first packet. Kprobes need CO-RE field access aya lacks; cgroup `connect4/6`, `sendmsg4/6`, `sock_create` hooks give pid/cgroup and stable context fields. | `procmap.rs`, `main.rs` (`tick`) | A, C, S | P1 (redesigned) |
| 7 | Flow key includes `ifindex` and assumes egress src = local. Forwarded/bridged traffic gets local/remote wrong and is counted once per hop. Rules need their own maps (LPM trie, port hash, cookie/cgroup), never LRU (eviction = fail-open). | `netmon-common/src/lib.rs` (`FlowKey`) | A, C | P2, P6 |
| 8 | All eBPF state is owned by the process: exit or crash removes every program and (future) rule. A daemon must pin programs, maps and links in `/sys/fs/bpf`. | `netmon/src/probe.rs` (`Probe`) | A | P7 |
| 9 | IPv6 extension headers not followed, IPv4 non-first fragments have no ports, VLAN-tagged frames without offload are not parsed. For a firewall this is a rule bypass. Needs a bounded header walk and a default verdict for unparsed packets. | `netmon-common/src/lib.rs` (`parse_packet`) | A, C | P2 |
| 10 | Owner identity `{pid, comm}`: comm is settable by any process (`prctl`), pid does not persist. Rules must use exe path / cgroup / systemd unit. | `netmon/src/procmap.rs` (`Owner`) | A | P1, P3 |

## Medium

| # | Finding | Where | Src | Status |
|---|---------|-------|-----|--------|
| 11 | `.pcap` save as root: `File::create` and `chown` follow symlinks (predictable name), file mode 0644 exposes payloads to all users. Use `create_new`, `O_NOFOLLOW`, mode 0600, `fchown`. | `netmon/src/capture.rs` (`save`) | S | P0 |
| 12 | README `setcap … +ep` on a 0755 binary gives packet sniffing to every local user; capability set is larger than needed. | `README.md` (Run) | S | P0 (doc) |
| 13 | Per-CPU flow map ≈ 268 MiB kernel memory on 128 CPUs; spoofed 5-tuples evict real flows. | `netmon-common/src/lib.rs` (`MAX_FLOWS`) | S | P0 (size from CPU count) |
| 14 | Map iteration can return the same key twice after an LRU eviction; the duplicate is processed with delta 0 and zeroes the rate. | `netmon/src/probe.rs` (`snapshot`), `collector.rs` (`ingest`) | C | P0 |
| 15 | Interface totals are sums of live flows, so they drop when idle flows expire. | `netmon/src/collector.rs` (`update_ifaces`) | C | P0 |
| 16 | Per tick: full `/proc/*/fd` scan and 2 syscalls per flow, on the UI thread. | `procmap.rs` (`read_owners`), `probe.rs` (`snapshot`) | C, A | P0 (inode cache), P7 |
| 17 | Interface capture on `lo` records each packet twice (ingress + egress). | `netmon-ebpf/src/main.rs` (`handle`) | C | P0 |
| 18 | Selected row is an index; with rate sort the row under the cursor changes every tick. | `app.rs`, `ui.rs` | C | P0 |
| 19 | Interface hot-plug by 2-tick poll: new interfaces unfiltered for up to 2 s. Use netlink link events. | `main.rs` (`tick`) | A | P2 |
| 20 | UI, collector, probe and capture are tangled in `Monitor`; root parses untrusted packets. Daemon split needs DTOs; decode and pcap move to the client. | `main.rs`, `ui.rs` | A | P7 |
| 21 | One capture slot and ring; DNS answers and SNI need a permanent filtered stream. Decoder ignores DNS answers and compression pointers. | `lib.rs` (`CaptureConfig`), `decode.rs` (`dns`) | A | P4 |
| 22 | Netns: `/proc/net` is netmon's own namespace; no netns id in the flow key. | `procmap.rs` | A | P6 |

## Low

| # | Finding | Where | Src | Status |
|---|---------|-------|-----|--------|
| 23 | `--once` prints process names raw (terminal escapes via `prctl`); Unicode bidi/format chars in DNS names reach the TUI. | `main.rs` (`print_once`), `decode.rs` (`qname`) | S | P0 |
| 24 | Capture key set inconsistent when an insert fails (> 4 096 keys): stale keys stay in the kernel map; error repeats every tick. | `probe.rs` (`set_capture_keys`) | A, S, C | P0 |
| 25 | `L3_OFFSET` entries never removed: reused ifindex inherits a wrong offset; map fills after 1 024 tunnels. | `probe.rs` (`attach`, `attach_new`) | A, S, C | P0 |
| 26 | Racy first insert in the flow map: two CPUs can insert and one overwrites the other's count (per-CPU slot, rare). | `netmon-ebpf/src/main.rs` (`count`) | A | P0 |
| 27 | "ring drops" counts since load, not per capture. | `probe.rs` (`capture_drops`) | C | P0 |
| 28 | `expire_ticks` uses the unclamped interval; `--interval-ms 10` expires after 300 s. | `main.rs` (`Monitor::new`) | C | P0 |
| 29 | Stop discards packets still queued in the ring. | `probe.rs` (`capture_off`) | C | P0 |
| 30 | README: no minimum kernel; "every 2 s" is every 2 ticks; owner limits understated. | `README.md` | C | P0 |

## Test gaps (C)

- No tests for the main loop: pause/resume, start/stop capture, process
  capture sync.
- No tests for forwarded/bridged direction, duplicate-key snapshots, VLAN or
  IPv6 extension headers in the parser, ifindex reuse.
- No fuzz test over `decode()` (security reviewer's harness found item 1).
- No end-to-end test of the eBPF side (netns + veth pair).

## Decisions (2026-11-18)

- **Fail-open.** Packets the parser cannot read pass. Blocks live in the
  netmon process and end when it exits or crashes (until the daemon, Phase
  7).
- **Lockout guard.** Never blocked: loopback, the SSH session netmon runs
  in (`SSH_CONNECTION`), DNS to the local system resolver (127.0.0.53 and
  the stub addresses in `/etc/resolv.conf`, port 53).
- **Prompt mechanism (Phase 5, decided 2026-11-19).** Drop the first
  packet and rely on TCP retransmits; the first UDP datagram is lost.
  NFQUEUE may come later.

## Decisions needed before the firewall phases (original list)

1. **Prompt mechanism (Phase 5).** Options: (a) cgroup `connect` hook denies
   while a prompt is open: app gets `EPERM`, user retries; (b) drop the SYN in
   TC and rely on TCP retransmits (1 s, 3 s, …), UDP is lost; (c) NFQUEUE,
   which really holds packets but leaves eBPF for that path.
2. **Fail-open or fail-closed** when netmon/netmond exits or crashes, and for
   packets the parser cannot read.
3. **Lockout guard**: always allow SSH / a management interface, regardless of
   rules.
