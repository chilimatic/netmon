# Third review of netmon at fad53f7

Three independent read-only reviews (architect, critic, security reviewer)
on 2026-11-25. They cover the 46 commits after the second review
(`f576535..fad53f7`): notifier, timed rules, listener alerts, connection
log, block lists, profiles, usage and history, GeoIP, alerts, capture
filter, stream follow, devices, DNS log, bandwidth limits, learning mode,
server name blocks in the kernel and packaging.

The findings are merged here and duplicates are removed. The source of
each finding is **A** (architect), **C** (critic) or **S** (security). Items
marked "spot-checked" were read again in the code before this file was
written.

All three reviews ran `AYA_BUILD_SKIP=1 cargo test` (220 + 21 tests pass)
and found no regression of a finding of `docs/REVIEW2.md`. The security
review found no memory safety, path, symlink or terminal escape problem.

Verdict: the kernel and userspace contract is consistent (`CFG_*` indexes,
`sni_step` and `sni_hash`, `SNI_SELF` and `SNI_BELOW`). The main design
problem is that blocked names become host-wide address blocks, and that
untrusted name sources feed them (H1 to H4). Large block lists cost much
memory and stop the main loop on each rule change (R1, R2). Device
discovery needs eviction and fewer alerts (D1 to D3).

Status column: the state after the fixes of 2026-11-25 (commits
306d458, cdc36e3, 4900dd0 and the commit of the small fixes).

## Host blocks: trust and side effects

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| H1 | High | A blocked name becomes a block of its addresses for every program, for up to 1 hour, and it wins over every allow rule. One listed ad name on a shared CDN or front-end address blocks every other site on that address. The addresses learned from a ClientHello add only this side effect, because the kernel already drops the ClientHello. The README says that server name blocks work for "an address that serves many names" and two bullets later that the address is blocked "also for other names on it". | `netmon/src/monitor/ruleset.rs:103-114`, `monitor/hosts.rs:66-70,92-96`, `README.md` | A, C, S | fixed (306d458): only host patterns block addresses |
| H2 | Medium | Untrusted name sources feed the address blocks. A local user without privileges can block any address for the whole host for 1 hour: query an own DNS server that answers `ads.x.com A 140.82.112.3` (it counts as solicited), or send a ClientHello with a listed server name to that address. | `monitor/hosts.rs:37,61-69`, `netmon-ebpf/src/main.rs:731` | A, S | fixed (306d458): only resolver answers |
| H3 | Medium | The kernel sends every TCP segment from port 53, and userspace parses each one as a new DNS message after 2 length bytes. Data in the middle of a long answer (a TXT record of a remote domain) can then pass as A records. Spot-checked. | `netmon-ebpf/src/main.rs:816-821`, `monitor/hosts.rs` | A | fixed (306d458): first segment only |
| H4 | Medium | The set of blocked addresses has no limit. About 256 forged answers fill `HOST_BLOCKS` (16 384 entries). The addresses of real blocked names then fail with only a "map full" status. Each new address also bumps the generation, so every connection walks the rules again. | `monitor/hosts.rs:91-100`, `monitor/ruleset.rs:114-125`, `netmon/src/probe.rs:928-951` | S | fixed (306d458): 64 per name, 8192 total, oldest goes |

## Resources

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| R1 | Medium | `MAX_SNI_NAMES = 2_100_000` is above 2^21, so the kernel hash table gets 4 194 304 buckets: about 64 MiB at load, also with no names. A full map adds about 128 MiB. Together with the name sets in userspace this is a risk for `MemoryMax=1G`. Spot-checked (bucket count). | `netmon-common/src/lib.rs:135`, `netmon-ebpf/src/main.rs:130` | A | fixed (4900dd0): 2^21 |
| R2 | Medium | Each rule change (ask answer, notifier button, timed rule end, `b`, profile) runs `sync_sni`. It hashes up to 2 million names and builds a new map of about 70 MB on the main loop thread. Ticks and clients stop for that time. | `monitor/ruleset.rs:222`, `netmon/src/rules.rs:519-536`, `probe.rs:806-826` | A | fixed (4900dd0): signature cache |
| R3 | Low | The protocol has no subscription per client. The notifier gets the full snapshot every tick, but reads only the questions. | `netmon/src/daemon.rs:302-303`, `netmon/src/notify.rs:123` | A | open |

## Devices

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| D1 | Medium | The device table (4096) never drops a device and is saved to disk. One LAN host that sends ARP from random MAC addresses fills it for good: real new devices are not recorded after that. Each MAC also gives a "new device" alert with no limit per tick, a blocking `notify-send` and an mDNS lookup in a queue with no limit. | `netmon/src/devices.rs:504,607,921-930`, `monitor/mod.rs:490-495` | A, S | fixed (cdc36e3): eviction, 5 alerts per tick, bounded queue |
| D2 | Medium | During the learning window, new MAC addresses do not go to `new`, so `take()` reports "online again" for each device that answers the first sweep (with `device_changes`). The test sets `learn_until = None` and misses this. Spot-checked. | `devices.rs:522-524,647-650` | C | fixed (cdc36e3) |
| D3 | Medium | A MAC with two IPv4 addresses or two interfaces counts as a move at each read of `/proc/net/arp` (every 5 s): proxy ARP, a Wi-Fi extender with MAC NAT, a secondary address, wlan0 and eth0 on one subnet. With `device_changes` this gives a "moved" alert every 5 s, the name is cleared each time and the file is written every minute. | `devices.rs:483-503,850-856` | C | fixed (cdc36e3): other addresses kept |
| D4 | Low | The IPv6 neighbor dump (1 s receive timeout) and `own_ipv6` run while the thread holds the state mutex, so the tick waits. All lock errors are ignored: a panic in a thread turns discovery off without a message. | `devices.rs:812,849-863,630` | A | fixed (cdc36e3) |
| D5 | Low | Active scanning is on by default (ARP to up to 1024 addresses every 10 minutes, ping to ff02::1), and `ScanDevices` from the group `netmon` has no rate limit. Managed networks can report this as a scan. | `netmon/src/daemon.rs:213`, `devices.rs:831-845`, `monitor/mod.rs:342-356` | A, S | fixed (cdc36e3): scan once per minute; default on documented |

## Server name blocks and bandwidth limits

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| K1 | Low | The kernel server name block stops only programs that do not hide the name: a name in the third segment, a first segment under 6 bytes, a ClientHello in several TLS records, a final dot (`name.` has another hash, while userspace strips the dot), ECH and QUIC. The 64-bit FNV hash is never checked against the name: a crafted list entry could collide with a popular name. | `netmon-ebpf/src/main.rs:212,221-297`, `netmon-common/src/lib.rs:147` | A, S | partly fixed (4900dd0): final dot; the rest documented |
| K2 | Low | `sni_deny` stores a deny with `answered = 0`. A later generation bump decides the connection again as allow; only a retransmitted ClientHello is checked again. A change of the server name set does not bump the generation. | `netmon-ebpf/src/main.rs:300-309`, `probe.rs:806-826` | A | fixed (4900dd0): sticky deny |
| K3 | Low | Limits name the exe. A copy of the binary under another path, a socket passed to a process without a limit, or an evicted `CONNS` entry (ingress) avoids the limit. The README does not say this. | `netmon-ebpf/src/main.rs:315-337` | S | documented |
| K4 | Low | `take_tokens` sets `last_ns` also when `now` is older (another CPU). A later packet gets the same time credited again. A simulation with a 900 µs skew passed 14.2 MB instead of 10.2 MB; real skew is in µs. | `netmon-common/src/lib.rs:197-206` | C | fixed |
| K5 | Low | The minimum bucket of 128 KiB makes small limits loose (0.01 MB/s allows a 13 s burst). A GSO packet over 128 KiB (BIG TCP) would always be dropped (unconfirmed). | `netmon-common/src/lib.rs:161,193-196` | A | documented |
| K6 | Low | If `set_limits` fails after `set_rules`, `CFG_LIMITS` and the old entries stay in the kernel, and the UI shows the new limit. | `probe.rs:828-842`, `monitor/ruleset.rs:219-221` | A | fixed |
| K7 | Low | `refresh_conns` treats the connection state as active only with rules or a default other than allow. It ignores `CFG_LIMITS` and `CFG_SNI`, so a flow denied by its server name shows no verdict. | `monitor/ruleset.rs:192` | A | fixed |
| K8 | Low | `L` with an asymmetric limit from the file (up 0.5, down 5) goes to 20/20, not to off as the doc comment says, and makes the limit symmetric. | `netmon/src/client.rs:196-198,418-426` | C | fixed |

## Other

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| O1 | Low | The profile picker lists `/etc/netmon/profiles`, but netmond uses the directory next to `--rules`. With another `--rules` path, `P` shows the wrong profiles. | `client.rs:263`, `monitor/ruleset.rs:263-275` | C | fixed |
| O2 | Low | A profile switch also clears the limits and `[alerts]`. README and ROADMAP name only rules, default, hosts and lists. | `monitor/ruleset.rs:330-335` | C | documented (intended: a profile is a full configuration) |
| O3 | Low | Learning mode suggests inbound rules without a port for replies from servers on high ports (WireGuard 51820, STUN 3478 and 19302, 5228). The exe path from the log is compared as text, so a rule with a symlink path does not count and is suggested again. | `netmon/src/learn.rs:93-104,125` | C | partly fixed: replies to own outbound left out; symlink documented |
| O4 | Low | Follow stream marks a segment that was captured but arrived out of order as missing. The README says "missing" means a packet that the capture lost. | `netmon/src/stream.rs:121-136` | C | fixed |
| O5 | Low | Usage can count a day twice: the history file is written before the file of today. If the second write fails after a day change, the next start adds the day twice. The UI reads the two files one after the other and can show it twice for up to 10 s. | `netmon/src/usage.rs:297-304,205-208` | C | fixed (merge takes the larger value) |
| O6 | Low | Country alerts: a flow is marked as checked before its program is known, so it never alerts. A full `seen` set stops alerts without a message. A GeoIP file that is missing at the first check turns the feature off until a restart. | `netmon/src/monitor/alerts.rs:98-126` | A | fixed |
| O7 | Low | A package upgrade does not restart netmond, and the protocol version must match. After an upgrade the new TUI is refused until a manual restart. The notifier stays silent after the first error. | `packaging/arch/netmon.install:13`, `daemon.rs:456`, `notify.rs:88-89` | A | partly fixed: .deb restarts; Arch prints the hint (Arch packages do not restart daemons); notifier shows each new error |
| O8 | Low | The update helpers: listupdate has no `--proto-redir`, so a redirect to http is possible. The GeoIP script has no `--proto`. Both units run as root with write access to more than they need. | `netmon/src/listupdate.rs:119`, `dist/netmon-geoip-update:24`, `dist/netmon-*.service` | S | partly fixed: https after redirects; helpers still run as root |
| O9 | Low | `usage-history.json` keeps 400 days of destinations per program for all users, readable by the group `netmon`. Before, the group saw only live data. | `usage.rs:19-28,309-323` | S | documented |
| O10 | Low | Docs: ROADMAP says that usage is kept 90 days (code: 400). The README key table does not have `h` and `H` of the question window. | `docs/ROADMAP.md:481`, `README.md:345` | C | fixed |
| T1 | Low | Missing tests: the kernel walk of `sni_blocked` (offsets, `SNI_PENDING` skip and left, 32 extensions) has only a live test. Also not tested: the learning window with `take()`, a MAC with several addresses, the profile picker with `--rules`, out-of-order segments in `follow`. | `netmon-ebpf/src/main.rs:221-295`, `devices.rs` tests | C | partly fixed: sni_walk host tests, device state tests, stream reorder test |

## Fix order (proposal)

1. H1 to H4: block addresses only for names from explicit host patterns
   or a trusted resolver, never for names from a ClientHello alone; parse
   only the first TCP DNS segment of an answer; limit the blocked address
   set and evict the oldest learned entries.
2. D1 to D3: evict old devices and limit new-device alerts; count a MAC
   with several addresses as one device with several addresses; start the
   online tracking after the learning window.
3. R1, R2: size `SNI_BLOCKS` to 2^21 or at load time; build the server
   name entries only when lists or host patterns change.
4. K2, K4, K6, K7, K8, O1, O2, O5, O10: small fixes.
5. README: K1, K3, K5, O3, O9 as documented limits.

## Found during the fixes

| # | Sev | Finding | Where | Src | Status |
|---|-----|---------|-------|-----|--------|
| N1 | Low | `systemctl restart netmond` leaves about 3 seconds without rules, also without host and server name blocks: the clean stop removes the pins, and loading the programs and rules takes about 3 s. A crash keeps the old rules. Found when a test ran right after a restart. | `netmon/src/daemon.rs`, `probe.rs` (`unpin`, `commit_pins`) | live test | documented |
