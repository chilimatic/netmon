# netmon

Terminal UI that shows open network connections, the process that owns each
one, the interface it uses, and live upload/download rates. Linux only.

## How it works

- eBPF TC programs (`netmon-ebpf`) run on ingress and egress of every
  interface. They parse IPv4/IPv6 + TCP/UDP headers and count bytes and
  packets per flow and interface in an LRU per-CPU hash map.
- Userspace (`netmon`) reads the map once per refresh interval (default 1 s,
  `--interval-ms`), computes rates, and maps each flow to a process with
  `/proc/net/{tcp,udp}{,6}` and `/proc/<pid>/fd`.
- New interfaces (containers, VPNs) are attached within 200 ms: netmon
  listens for rtnetlink link events. If that socket cannot be opened, it
  falls back to a rescan every second refresh interval.

## Requirements

- Linux 5.17 or later (the rule table walk uses `bpf_loop`). Tested only
  on 6.18; older kernels are supported by design, not yet by test.
  - 6.6 and later: programs attach with tcx and run next to other tc/tcx
    programs.
  - Before 6.6: netmon adds a `clsact` qdisc to each interface (if missing)
    and attaches with netlink. The qdisc stays after netmon exits; remove it
    with `tc qdisc del dev <iface> clsact` if nothing else uses it.
- No BTF needed: the programs read packet bytes only, no kernel structs.

## Build

Prerequisites (once):

```sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

Build:

```sh
cargo build --release
```

Userspace only, for tests without `bpf-linker` (the binary then refuses to run):

```sh
AYA_BUILD_SKIP=1 cargo test -p netmon -p netmon-common
```

## Run

Without the daemon (below), netmon monitors in its own process. It loads
eBPF programs and reads every process's sockets, so it runs as root:

```sh
sudo ./target/release/netmon
```

### Daemon (netmond)

`netmond` runs the monitor and the firewall as root. The `netmon` UI then
runs as a normal user and connects to it:

```sh
sudo groupadd --system netmon
sudo usermod -aG netmon "$USER"          # log in again afterwards
sudo ./target/release/netmond             # add --rules PATH or --ask here
./target/release/netmon                   # in another terminal, no sudo
```

- `netmond` listens on `/run/netmon.sock` (`--socket PATH`). The socket is
  `root:netmon`, mode `0660`. The daemon also checks every client with
  `SO_PEERCRED`: only root and members of the group can connect. Without
  the group, only root can connect.
- `netmon` connects when the socket exists. `netmon --local` runs the
  monitor in its own process (root needed), as before.
- `--rules`, `--ask`, `--interval-ms` and `--expire-secs` are options of
  the monitor. With a daemon, give them to `netmond`.
- Rules, questions and captures are shared by all connected UIs. The first
  answer to a question counts. Pause, filter and sort are per UI.
- Captured packets go to the UI as raw bytes. The UI decodes them and
  writes the `.pcap` file, as your user, in its working directory.
- When the last UI closes, the rules stay in force. In ask mode with no UI,
  questions time out after 30 s and the connections are denied.
- `netmond` stops on `SIGTERM` or `Ctrl-C`. Then it removes the socket and
  all its programs: no rule is in force after a clean stop.

#### Rules survive a crash

`netmond` pins its links under `/sys/fs/bpf/netmon` (TC per interface,
cgroup hooks, exec tracepoints). A pinned link stays attached when the
process ends, and keeps its program and maps. So if `netmond` crashes or
gets `kill -9`, **the last rules stay in force**:

- Blocks and the default action stay. In ask mode, nobody answers: new
  outbound connections that no rule decides are dropped until `netmond`
  runs again.
- Temporary rules (from `b`, or `a`/`d` in ask mode) stay too, until the
  restart. The restart loads only the rules file.
- Counting and hostnames stop: nothing reads the maps.

To recover, start `netmond` again: it removes the old pins and attaches new
programs, then loads the rules file. For a short time during that start no
rule is in force. To remove the old rules without a start:

```sh
sudo rm -r /sys/fs/bpf/netmon
```

Check what is pinned with `sudo ls /sys/fs/bpf/netmon` and
`sudo bpftool link list`. The local mode (`netmon --local`) pins nothing:
when it ends, its rules end too.

If the socket file stays after a crash, `netmon` reports that the daemon
does not run. The next start of `netmond` replaces the file. A second
`netmond` refuses to start while one runs.

The wire format is one JSON object per line (`netmon/src/proto.rs`).

### Install as a service

The daemon runs from boot, so rules are in force with nobody logged in. The
UI runs as a member of group `netmon`, without sudo.

```sh
cargo build --release
sudo install -o root -g root -m 0755 target/release/netmond target/release/netmon /usr/local/bin/
sudo groupadd --system netmon
sudo usermod -aG netmon "$USER"          # log in again afterwards
sudo install -d -o root -g root -m 0755 /etc/netmon
sudo install -o root -g root -m 0644 docs/rules.example.toml /etc/netmon/rules.toml   # optional
sudo install -o root -g root -m 0644 dist/netmond.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netmond
netmon
```

`docs/rules.example.toml` sets `default = "ask"`. Change it to `"allow"`, or
remove the line, if you do not want ask mode.

- Options go into a drop-in: `sudo systemctl edit netmond`, then
  `[Service]`, an empty `ExecStart=` and `ExecStart=/usr/local/bin/netmond --ask`.
- The unit starts before `network-pre.target`, so the rules apply before
  the network comes up.
- `systemctl stop netmond` is a clean stop: all rules end.
  `systemctl restart netmond` stops cleanly and starts again: for a moment
  no rule is in force, then the rules file loads. Temporary rules are lost.
- After a crash the rules stay in force (see "Rules survive a crash"), and
  systemd starts netmond again after 2 s (`Restart=on-failure`).
- Log: `journalctl -u netmond`.
- After a rebuild, run the `install` line for the binaries again, then
  `sudo systemctl restart netmond`. A running `netmon` UI loses its
  connection and must be started again.

Remove:

```sh
sudo systemctl disable --now netmond
sudo rm /etc/systemd/system/netmond.service /usr/local/bin/netmond /usr/local/bin/netmon
sudo systemctl daemon-reload
```

### Without sudo (file capabilities)

| Capability | Why |
|------------|-----|
| `cap_bpf` | load programs, create maps |
| `cap_net_admin` | attach TC programs, add `clsact` |
| `cap_perfmon` | without it the verifier is stricter for non-root loaders; may not be needed |
| `cap_sys_ptrace` | read `/proc/<pid>/fd` links of other users' processes |
| `cap_dac_read_search` | list `/proc/<pid>/fd` of other users' processes |

Without the last two netmon still runs, but shows only your own processes as
owners. This set is derived from the kernel's checks and not yet tested
without root.

> **Security:** anyone who can run a binary with these capabilities can read
> every packet on the host, including other users' traffic and anything not
> encrypted. Never set them on a file in `target/` or any directory your
> user can write: a rebuild drops the capabilities, and a writable file can
> be replaced. Install a root-owned copy that only one group may run:

```sh
sudo groupadd --system netmon
sudo usermod -aG netmon "$USER"          # log in again afterwards
sudo install -o root -g netmon -m 0750 target/release/netmon /usr/local/bin/netmon
sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_sys_ptrace,cap_dac_read_search+ep /usr/local/bin/netmon
netmon
```

Repeat the `install` and `setcap` lines after every rebuild.

Without the TUI: `netmon --once 3` samples 3 s and prints a table.

Keys: `←`/`→` (or `Tab`, `1-5`) switch view, `b`/`B` block remote IP/port, `Esc` clear filter, `Enter` capture the selected row, `r`/`t`/`n` sort by rate/total/name, `/` filter, `h` hostnames or addresses, `v` show veth/bridge rows,
`p` pause the view (counting goes on), `g` toggle the traffic graph, `↑↓` select, `q` quit.

The graph on top shows the total traffic of the physical interfaces (those
with a `device` in `/sys/class/net`; all but `lo` if there are none) for the
last 120 samples: download above the zero line, upload below. Each half has
its own scale (shown on the y axis).

## Hostnames

The Remote column shows a hostname where netmon knows one:
`example.com:443`. `h` switches between names and addresses; the detail
line under the table always shows the address and where the name came
from, and `/` also finds hostnames.

- TLS (`name from tls`): the server name (SNI) the client sent in its
  ClientHello on this connection. It wins over DNS: one address can serve
  many names, SNI says which one this connection asked for. Works with
  encrypted DNS too.

- The kernel passes DNS answers (UDP from port 53, every interface) to
  netmon. Each A/AAAA address gets the name that was asked, not the CDN
  name behind a CNAME. Names stay 1 hour after the last answer; up to 4096.
- Only answers seen while netmon runs count: connections opened before it
  started show addresses until the next lookup of that name.
- Encrypted DNS (DNS over TLS/HTTPS, e.g. in browsers) gives no DNS
  names; SNI still names their TLS connections.
- No SNI for QUIC (HTTP/3, encrypted ClientHello). With Encrypted Client
  Hello (ECH) the name shown is the outer one, e.g. `cloudflare-ech.com`.
- Browsers' ClientHellos (post-quantum key shares, ~1.8 KB) span two
  segments. netmon reads up to 4 KiB per packet, which covers GSO
  super-packets, and otherwise also reads the next segment of the
  connection and joins both.
- DNS packets are untrusted input: the parser bounds every read and gives
  up on malformed answers.

## Blocking

In **Connections**, `b` blocks the selected row's remote address and `B` its
remote port (TCP or UDP). In **Processes**, `b` blocks every process running
the selected process's exe, including ones started later. Press the key
again to unblock. Blocked rows turn
red. The **Rules** tab (`5`) lists every rule in match order with its hit
count (connections and socket calls it decided); `d` removes the selected
one.

Rules form an ordered list: the first rule that matches decides. TCP and
UDP traffic no rule matches gets the default action (`allow` unless the
rules file says `default = "deny"`); other protocols (ICMP) pass. A new
block goes on top. Up to 256 rules.

The kernel decides each TCP or UDP connection once, on its first packet,
and remembers the verdict and who opened it (up to 65 536 connections,
oldest forgotten first). Later packets, replies included, reuse the
verdict, so `default = "deny"` with `direction = "out"` allows replies to
your own connections. A rule change decides every connection again. The
detail line under the Connections table shows `opened in/out, allowed/
denied`.

- New connections and UDP sends to a blocked destination fail with
  `Operation not permitted` (cgroup `connect`/`sendmsg` hooks). Packets of
  existing connections and traffic without a local socket are dropped in
  TC on every interface.
- Exe blocks follow `exec` and `fork` through kernel tracepoints. A program
  started through a symlink (`python3` -> `python3.13`) is caught by the
  `/proc` scan at the next refresh instead, so it can connect for up to one
  refresh interval.
- Blocks end when netmon exits or crashes (fail-open). Packets netmon
  cannot parse pass.
- Never blocked (lockout guard): loopback, the SSH session netmon runs in,
  DNS (port 53) to the nameservers in `/etc/resolv.conf`, DHCP and DHCPv6
  (UDP 67, 68, 546, 547), and TCP/UDP fragments without ports.
- With default deny, allow what the host needs, e.g. your DNS upstream if
  a local resolver (systemd-resolved) forwards to it, and NTP.
- A connection forgotten while open (map full) is decided again on its
  next packet, which may then count as opened by the other side.

### Rules file

At start netmon loads `/etc/netmon/rules.toml` (another file with
`--rules PATH`). A missing default file is fine; a missing `--rules` file
is an error. Rules keep their file order; blocks made in the UI go on top.

```toml
# curl may reach HTTPS only.
[[rule]]
action = "allow"
process = "/usr/bin/curl"
proto = "tcp"
port = 443
comment = "web"

[[rule]]
action = "deny"
process = "/usr/bin/curl"

[[rule]]
action = "deny"
remote = "10.0.0.0/8"      # or one address, IPv6 too
port = "8000-8100"         # or one number; without proto: tcp and udp
```

- `action` is required. Every other field is optional and narrows the
  match; a rule with only `action` matches all traffic.
- `direction = "out"` matches connections this host opened, `"in"` ones
  the remote host opened.
- Top level `default = "deny"` denies TCP and UDP traffic no rule allows.
  Inbound exe rules use the process that bound the local port.
- `process` is an absolute exe path. Process names (`comm`) are not
  accepted: any process can choose its own.
- `remote` must not have host bits set (`10.1.0.0/8` is refused).
- netmon runs as root, so whoever can write the file controls the
  firewall. The file and its directory must belong to root and must not
  be writable by group or others:

  ```sh
  sudo install -d -o root -g root -m 0755 /etc/netmon
  sudo install -o root -g root -m 0644 rules.toml /etc/netmon/rules.toml
  ```

- On any error (unsafe owner or mode, bad TOML, bad field) netmon names the
  line and the reason in the status line and starts without the file's
  rules.
- `s` in the Rules tab writes every rule (file and UI) and the default back
  to the file, in match order. It creates `/etc/netmon` (0755) if missing,
  writes a temp file (0644) and renames it over the old one. Only the
  `comment` fields are kept: other `#` comments of a hand-written file are
  lost.

### Ask mode

`sudo netmon --ask` (or `default = "ask"` in the rules file) asks before
outbound TCP or UDP connections that no rule decides. There is one question
per program; all its waiting connections are listed by destination:

```
┌ netmon asks ─────────────────────────────────────────────────────────┐
│firefox (pid 4242, user j)   exe /usr/lib/firefox/firefox              │
│wants 12 connections to 3 destinations:                                │
│> example.com (93.184.215.14)  tcp 443  ×9                             │
│  ocsp.example.net (1.2.3.4)  tcp 80  ×2                               │
│  93.184.215.15  udp 443  ×1                                           │
│                                                                       │
│scope ←→ program   rule: exe /usr/lib/firefox/firefox                  │
│a allow  A allow always  d deny  D deny always   o/x ... once  ↑↓ select│
│no answer in 27 s: deny once                                           │
└───────────────────────────────────────────────────────────────────────┘
```

- `←`/`→` choose how wide an answer is: **program** (any destination),
  **port** (this protocol and port, any host) or **destination** (this
  address and port). `↑`/`↓` select the destination the last two use.
- `a`/`d` make an allow/deny rule for that scope until netmon exits (`tmp`
  in the Rules tab, never saved). `A`/`D` make a lasting rule; `s` in the
  Rules tab saves it. Every waiting connection the new rule covers is
  decided at once, in every question.
- `o`/`x` allow/deny only the selected destination's waiting connections.
  These answers stay with the connections through later rule changes.
- The kernel drops a waiting connection's packets. TCP sends its SYN again
  after about 1, 3, 7 and 15 s, so it goes through at its next try. UDP
  has no such retry: the first datagram is lost and the program's own
  retry (e.g. a DNS resolver's) gets through.
- No answer in 30 s: the waiting connections are denied once.
- Unmatched inbound connections are denied in ask mode. The lockout guard
  (loopback, SSH session, resolver DNS, DHCP) is never asked.
- **Unknown process:** traffic without a local socket (forwarded from
  containers, VMs, Docker bridges) has no program. Its question starts at
  **port** scope, and `a`/`d`/`A`/`D` make rules without an exe, which
  apply to every process. There is no program scope for it.
- `--once` cannot ask: asked connections stay dropped.
- `docs/rules.example.toml` pre-allows common system services
  (systemd-resolved, timesyncd, NetworkManager).

## Packet capture

Select a row in **Connections**, **Processes** or **Interfaces** and press
`Enter`. netmon switches to the **Capture** tab (`4`) and shows:

- a packet list: number, time since start, direction (↑ out, ↓ in),
  interface, source, destination, protocol, length and a summary
  (TCP flags/seq/ack, DNS queries, ARP, ICMP);
- the decoded headers of the selected packet (Ethernet, VLAN, ARP, IPv4,
  IPv6, TCP, UDP, ICMP, DNS);
- a hex/ASCII dump of the captured bytes.

Keys in the Capture tab: `↑↓`/`PgUp`/`PgDn`/`Home` select, `End` or `f`
follow new packets, `s` save as `.pcap`, `c` clear, `x` stop.

- The first 1500 bytes of each packet are kept; the original length is
  recorded. Up to 20 000 packets stay in memory, oldest dropped first.
- `s` writes `netmon-<unix time>.pcap` to the current directory, readable by
  Wireshark or `tcpdump -r`. Under `sudo` the file is given to your user.
- A **process** capture follows the process: its new connections join within
  one refresh interval, so the very first packets (e.g. the SYN) of a new
  connection can be missed.
- Devices without a link layer (tun, wireguard) get a dummy Ethernet header
  with zero MAC addresses, so all packets share one pcap link type.
- "ring drops" counts packets this capture lost because the kernel ring
  buffer (8 MiB) filled faster than the UI read it.
- `x` stops the capture and keeps the packets still queued in the kernel.
- Saved files have mode 0600, are never overwritten, and symlinks at the
  target name are not followed.

## Limits

Owners come from kernel hooks, best source first (the detail line under
the Connections table names it):

1. `kernel`: the process that created, connected or sent on the flow's own
   socket.
2. `/proc`: the process holding the socket with the exact addresses.
3. `kernel (bind)`: the process that bound the local address (servers, UDP
   receivers). Accepted connections have no connect hook, so they land here
   when `/proc` is too late.
4. `/proc (port)`: a guess by local port.

A weaker source never replaces a stronger one. Limits of the `/proc`
sources:

- Sockets that open and close between two refreshes (a DNS query, a short
  `curl`) are often never seen and show as `?`.
- Containers (other network namespaces): their sockets are read from
  `/proc/<pid>/net/*` of a process in each namespace, and their rows show
  `container:<name>/<process>` (Docker name, Podman id, else
  `netns:<inode>`), owner source `container /proc`. On veth and bridge
  interfaces the match is exact (state `container`); on the uplink after
  masquerade it is by remote end and local port (state `nat`), which fails
  when NAT changed the port. These tables are read in the background, at
  most every 3 s and only while some flow has no owner, because each read
  walks the kernel's UDP hash table once per namespace.
- Rules cannot name a container: on the host its packets have no socket.
  Ask mode names the container in the question but makes rules without an
  exe (port or destination for every process).
- Listeners and unconnected UDP sockets are matched by port and bound
  address (or a wildcard bind). A process that binds a port gets the
  traffic of that port.
- A socket shared after `fork` shows the first process found that holds it.
- The process name is `comm`, which every process can change itself. Do not
  use it as proof of identity. The Processes tab and the detail line under
  the Connections table show the exe path, user and systemd unit, read from
  `/proc/<pid>/exe` and `/proc/<pid>/cgroup` once per process. A process that
  exits before netmon reads them shows `-`.

Counting:

- Traffic that crosses several interfaces (veth, bridge, uplink) is seen
  once per interface. The header total and the graph count physical
  interfaces only, so each byte counts once; VPN (tun) traffic counts as
  its encrypted packets on the uplink. Connections and Processes hide rows
  of bridges and veth/vlan interfaces; `v` shows them. The Interfaces tab
  lists every interface with its kind.
- Forwarded traffic (router, bridge) is shown as if the host sent it: on
  egress the source is taken as local.
- Up to 2 VLAN tags and 6 IPv6 extension headers are followed. Fragments
  after the first, and packets with more headers, count with port 0.
- Interface totals count from netmon's start, not from boot.
