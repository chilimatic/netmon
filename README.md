# netmon

netmon is a network monitor and a firewall for one Linux host. It runs in a
terminal. It shows each open connection, the process that owns it, the
interface it uses, and its upload and download rates. It can block traffic,
ask before a program connects, name the remote hosts, and capture packets.

netmon has two parts:

- `netmond`, the daemon (a background service). It runs as root, loads the
  eBPF programs into the kernel and enforces the rules.
- `netmon`, the user interface. It runs as a normal user and connects to
  `netmond` over a Unix socket.

eBPF is a way to run small, checked programs inside the Linux kernel. netmon
uses eBPF to see every packet and every socket call without a kernel module.

Contents:

1. [Overview](#overview)
2. [Network diagram](#network-diagram)
3. [Requirements](#requirements)
4. [Install](#install)
5. [Run](#run)
6. [The user interface](#the-user-interface)
7. [Hostnames](#hostnames)
8. [Firewall](#firewall)
9. [Packet capture](#packet-capture)
10. [The daemon](#the-daemon)
11. [Decisions](#decisions)
12. [Limits](#limits)
13. [Development](#development)

## Overview

```
 ┌──────────────────────┐                ┌───────────────────────────────────┐
 │ netmon (user)        │  JSON lines    │ netmond (root)                    │
 │  shows the snapshot, │◄──────────────►│  engine: tick every 1 s,          │
 │  decodes packets,    │ /run/netmon.   │  owners, rules, hostnames,        │
 │  writes .pcap files  │ sock (0660)    │  questions, capture               │
 └──────────────────────┘                └──────┬───────────────────▲────────┘
          (more UIs can connect)                │ write rules       │ read maps
                                                │ and verdicts      │ and rings
 user space                                     │                   │
 ═══════════════════════════════════════════════╪═══════════════════╪═════════
 kernel                                         ▼                   │
        ┌──────────────────────── eBPF maps and ring buffers ──────────────────┐
        │ RULES  RULE_CFG  CONNS  GUARD  EXE_IDS  TGID_EXE    (firewall)       │
        │ FLOWS  SOCK_OWNER  LISTENERS                        (counting)       │
        │ NAMES  ASKS  PACKETS                                (event rings)    │
        └──────▲──────────────────────────▲─────────────────────────▲──────────┘
               │                          │                         │
     cgroup socket hooks           TC programs, ingress       tracepoints
     (every process on the host)   and egress, on every       sched_process_exec
                                   interface                  task_newtask
                                                              sched_process_exit
```

The kernel programs do the work that must happen at each packet or socket
call:

- The TC programs (traffic control hooks) count bytes per connection and
  per interface, and drop packets that the rules deny.
- The cgroup socket hooks see every `connect`, `sendmsg`, `bind` and socket
  create of every process. They record which process owns which socket, and
  they refuse new connections that the rules deny.
- The tracepoints see each `exec`, each new process and each process exit.
  They keep the map of "process runs this exe" current, so that rules for
  an exe apply at once. New threads are not recorded: rules look up
  processes, and thread ids would fill the map.

`netmond` reads the maps once per tick (1 s by default), computes the
rates, finds the owner of each connection, and sends a snapshot to each
connected UI. The UI draws the snapshot and sends back requests, for
example "block this address".

## Network diagram

```
   process (curl, pid 4242)                     container "web"
        │ socket(), connect(), sendmsg()         │ its own network namespace
        ▼                                        ▼
 ┌─────────────────────────────┐            eth0 (inside the container)
 │ cgroup hooks                │                 │
 │  sock_create   record owner │                 │ veth pair
 │  connect4/6    allow, deny  │                 │
 │  sendmsg4/6    allow, deny  │            vethXXXX ── [TC ingress, egress]
 │  post_bind4/6  listeners    │                 │
 │  sock_release  forget       │            docker0 bridge ── [TC ingress, egress]
 └──────────────┬──────────────┘                 │
                ▼                                ▼
        ┌───────────────────────── host network stack ──────────────────┐
        │ routing, NAT (masquerade for containers), local delivery      │
        └───────┬──────────────────────┬────────────────────┬───────────┘
                ▼                      ▼                    ▼
           enp5s0 (physical)      wg0 / tun0 (VPN)        lo (loopback)
           [TC ingress, egress]   [TC ingress, egress]    [TC ingress, egress]
                │                      │
             network               encrypted, then sent again on enp5s0
```

Where netmon decides about a packet:

- A new connection or UDP send from a local process meets the cgroup hook
  first. If a rule denies it, the call fails with `Operation not permitted`
  and no packet leaves.
- Every packet passes the TC program of each interface it crosses. On its
  first packet, the kernel decides the connection and stores the verdict in
  `CONNS`. Later packets, replies included, use that verdict. A denied
  packet is dropped (`TC_ACT_SHOT`). An allowed packet continues to the
  next program (`TC_ACT_UNSPEC`), so other eBPF tools still run.
- Traffic of a container or VM has no socket on the host. Only the TC
  programs see it, on the veth, on the bridge and again on the uplink.

The same packet can cross three interfaces: veth, bridge and uplink. netmon
shows it on each, but the totals and the graph count only physical
interfaces. The section [Counting](#counting) gives the details.

## Requirements

- Linux 5.17 or later. The rule table walk uses `bpf_loop`. netmon was
  tested on 6.18 only.
  - On 6.6 and later, the TC programs attach with tcx and run next to other
    tc and tcx programs.
  - Before 6.6, netmon adds a `clsact` qdisc to each interface and attaches
    with netlink. The qdisc stays after netmon stops. If nothing else uses
    it, remove it with `tc qdisc del dev <iface> clsact`.
- cgroup v2, mounted at `/sys/fs/cgroup`.
- The BPF file system at `/sys/fs/bpf`. systemd mounts it.
- No BTF and no kernel headers. The programs read packet bytes and stable
  context fields only.

## Install

### Build

Install the toolchain once:

```sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

Build both binaries:

```sh
cargo build --release
```

The binaries are `target/release/netmond` and `target/release/netmon`.

### Install as a service

With this installation, the rules are in force from boot, also when nobody
is logged in. Run the commands from the repository directory:

```sh
sudo install -o root -g root -m 0755 target/release/netmond target/release/netmon /usr/local/bin/
sudo groupadd --system netmon
sudo usermod -aG netmon "$USER"
sudo install -d -o root -g root -m 0755 /etc/netmon
sudo install -o root -g root -m 0644 docs/rules.example.toml /etc/netmon/rules.toml
sudo install -o root -g root -m 0644 dist/netmond.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netmond
```

Then log out and log in again, so that your session gets the group
`netmon`. Start the UI without sudo:

```sh
netmon
```

The rules file is optional. `docs/rules.example.toml` sets
`default = "ask"` and allows common system services. If you do not want ask
mode, change the line to `default = "allow"` or remove it.

To give options to the daemon, run `sudo systemctl edit netmond` and enter:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/netmond --ask
```

After a rebuild, install the binaries again and restart the service:

```sh
sudo install -o root -g root -m 0755 target/release/netmond target/release/netmon /usr/local/bin/
sudo systemctl restart netmond
```

A running UI loses its connection at the restart. Start it again.

To remove netmon:

```sh
sudo systemctl disable --now netmond
sudo rm /etc/systemd/system/netmond.service /usr/local/bin/netmond /usr/local/bin/netmon
sudo systemctl daemon-reload
```

## Run

netmon has three ways to run:

| Command | Who | What |
|---|---|---|
| `netmon` | member of group `netmon` | UI connected to `netmond` |
| `sudo netmon --local` | root | Monitor and UI in one process, no daemon |
| `netmon --once 3` | as above | Samples 3 s, prints the connections as a table, exits |

`netmon` connects to `netmond` if the socket `/run/netmon.sock` exists.
Otherwise, it runs the monitor in its own process, which needs root. If you
are not root and the daemon does not run, `netmon` tells you so.

Options of the monitor:

| Option | Default | Meaning |
|---|---|---|
| `--interval-ms N` | 1000 | Time between two samples (at least 100) |
| `--expire-secs N` | 30 | Remove a connection after N s without traffic |
| `--rules PATH` | `/etc/netmon/rules.toml` | Rules file. A missing default file is not an error. |
| `--ask` | off | Ask mode: ask before outbound connections that no rule decides |
| `--guard-port PORT` | 22 for `netmond`, none for `--local` | Local TCP port that no rule can block. Repeat for more, `0` for none. |

With a daemon, give these options to `netmond`, not to `netmon`. `netmon`
refuses `--rules` and `--ask` when it connects to a daemon.

Options of the UI: `--socket PATH` (another socket) and `--local` (no
daemon). Options of the daemon: `--socket PATH` and `--group NAME` (the group
that can connect, default `netmon`).

## The user interface

### Layout

```
 netmon   ↑ 1.2M/s  ↓ 8.4M/s   flows 213  RULES 4  ASK   <status message>     1
 ┌────────────────────────────────────────────────────────────────────────┐
 │ ↓ download (green) above the zero line                                 │   2
 │─────────────────────────────── 120 samples ────────────────────────────│
 │ ↑ upload (magenta) below the zero line                                 │
 └────────────────────────────────────────────────────────────────────────┘
  1 Connections   2 Processes   3 Interfaces   4 Capture   5 Rules              3
 Process      PID   Proto Local            Remote             Iface  State ...  4
 firefox      4242  tcp   10.0.0.2:51234   example.com:443    enp5s0 ESTAB
 ...
 93.184.215.14:443 (name from tls)   exe /usr/lib/firefox/firefox   ...         5
 q quit  ←→/1-5 view  Enter capture  b/B block ip/port  r/t/n sort ...         6
```

1. Header. It shows the total upload and download rate of the physical
   interfaces, the number of connections, and the firewall state:
   `RULES n` (number of rules), `DEFAULT DENY` or `ASK` (the default
   action), `[PAUSED]`, the capture state, and the last status message.
2. Traffic graph. It shows the total rate of the last 120 samples. Each
   half has its own scale. `g` hides it. A terminal with less than 20 lines
   does not show it.
3. Tabs. `←` and `→`, `Tab`, or `1` to `5` select a tab.
4. The table of the tab. `↑` and `↓` select a row. The selection stays on
   the same row when the order changes.
5. Detail line (Connections tab only). The section below explains it.
6. Key line. It shows the keys of the current tab, the sort order, the
   filter and the veth/bridge setting.

### Keys

| Key | Where | Action |
|---|---|---|
| `q`, `Ctrl-C` | everywhere | Quit |
| `←` `→` `Tab` `1`-`5` | everywhere | Select a tab |
| `↑` `↓` `PgUp` `PgDn` `Home` | tables | Select a row |
| `/` | tables | Type a filter. `Enter` keeps it, `Esc` clears it. |
| `Esc` | tables | Clear the filter (never quits) |
| `r` `t` `n` | tables | Sort by rate, by total bytes, by name |
| `h` | Connections | Show hostnames or addresses in the Remote column |
| `v` | Connections, Processes | Show or hide rows of bridges and veth/vlan interfaces |
| `p`, `Space` | everywhere | Pause the view. Counting goes on. |
| `g` | everywhere | Show or hide the traffic graph |
| `Enter` | Connections, Processes, Interfaces | Capture the packets of the selected row |
| `b` | Connections | Block or unblock the remote address |
| `B` | Connections | Block or unblock the remote port |
| `b` | Processes | Block or unblock the exe of the process |
| `d` | Rules | Remove the selected rule |
| `s` | Rules | Save all rules to the rules file |
| `s` `c` `x` `f` `End` | Capture | Save `.pcap`, clear, stop, follow new packets |
| `a` `A` `d` `D` `o` `x` | question window | Answer a question (see [Ask mode](#ask-mode)) |
| `Esc` | question window | Put the questions aside: the tab gets its keys back |
| `?` | everywhere | Show the questions again |

The filter finds rows whose process, PID, exe, user, unit, addresses,
hostname, interface or protocol contain the text. Upper and lower case are
the same.

### Connections tab

One row per connection and interface.

| Column | Content |
|---|---|
| Process | Process name (`comm`), `container:<name>/<process>` for a container, or `?` if unknown |
| PID | Process ID, or `-` |
| Proto | `tcp`, `udp`, `icmp`, `icmp6` or `other` |
| Local | Local address and port |
| Remote | Remote hostname and port, or the address (`h` switches) |
| Iface | Interface |
| State | TCP state from the socket table (`ESTAB`, `LISTEN`, ...), `container`, `nat` or `closed` |
| ↑ ↓ | Upload and download rate |
| Total | Bytes in both directions since netmon saw the connection |

A red row is blocked. The kernel verdict decides the color. If the kernel
has no verdict yet, the rules decide.

The detail line under the table shows the selected connection:

```
 93.184.215.14:443 (name from tls)   exe /usr/lib/firefox/firefox   user j   unit app-firefox.scope   owner from kernel   opened out, allowed
```

- The remote address, also when the Remote column shows the hostname, and
  where the name came from (`tls` or `dns`).
- The exe path, the user and the systemd unit of the owner. These come from
  `/proc/<pid>/exe` and `/proc/<pid>/cgroup`, and the process cannot change
  them.
- Where the owner came from. The section [Owners](#owners) lists the
  sources.
- Which side opened the connection and the kernel verdict, while rules are
  in force.

### Processes tab

One row per process, with the sum of its connections.

| Column | Content |
|---|---|
| Process, PID, User, Exe | The owner |
| Flows | Number of connections |
| ↑ ↓ Total | Sum of the rates and bytes of its connections |

A red row is a process whose exe is blocked.

### Interfaces tab

One row per interface, with its kind and its traffic since netmon started.
The box under the table shows the history of the selected interface.

| Kind | Meaning |
|---|---|
| `physical` | Has a device in `/sys/class/net/<name>/device`. Counted in the totals. |
| `bridge` | A bridge, for example `docker0`. Carries the traffic of its ports again. |
| `veth/vlan` | veth, vlan or macvlan. The same traffic also crosses another interface. |
| `other` | Loopback, tun, wireguard and the rest |

### Capture tab

The section [Packet capture](#packet-capture) explains it.

### Rules tab

One row per rule, in match order: number, action (green allow, red deny),
match, comment and hits. A hit is one connection or socket call that the
rule decided. A rule from an `a` or `d` answer shows `tmp`: it ends when
the monitor stops, and `s` does not save it. With no
rules, the tab explains how to make one.

### Question window

In ask mode, a yellow window opens over the tab when a program wants to
connect. While it is open, its keys have priority: in the Capture tab `x`
denies, in the Rules tab `d` denies. `Esc` puts the questions aside, and the
header then shows `n QUESTIONS WAITING (? shows)`. `?` shows them again.
The section [Ask mode](#ask-mode) explains the answers.

## Hostnames

The Remote column shows a hostname where netmon knows one, for example
`example.com:443`. netmon gets names from two sources:

- TLS (`name from tls`). This is the server name (SNI) that the client sent
  in its TLS ClientHello on this connection. It has priority over DNS,
  because one address can serve many names and SNI tells which name this
  connection asked for. It also works when DNS is encrypted.
- DNS (`name from dns`). The kernel passes each DNS answer (UDP from port
  53, on every interface) to netmon. Each A or AAAA address gets the name
  that was asked, not the CDN name behind a CNAME. A name stays for 1 hour
  after the last answer. netmon keeps up to 4096 names.

Limits:

- netmon sees only DNS answers that arrive while it runs. A connection that
  opened before shows its address until the next lookup of that name.
- Encrypted DNS (DNS over TLS or HTTPS) gives no DNS names. SNI still names
  the TLS connections.
- QUIC (HTTP/3) encrypts its ClientHello, so it has no SNI name. With
  Encrypted Client Hello (ECH), the name is the outer one, for example
  `cloudflare-ech.com`.
- A browser ClientHello is about 1.8 KB and can use two TCP segments. The
  kernel copies up to 4 KiB per packet, and otherwise also copies the next
  segment of the connection. netmon joins both.
- DNS and TLS packets come from the network. The parsers test the bounds of
  every read and stop at malformed data. Names are cleaned of control and bidi
  characters before the terminal shows them.

## Firewall

### Rules

Rules form an ordered list of up to 256 entries. The first rule that matches
decides. TCP and UDP traffic that no rule matches gets the default action:
`allow`, `deny` or `ask`. Other protocols (ICMP) pass.

A rule matches on any of these fields. A field that is not set matches
everything:

- remote network (address and prefix length)
- protocol (TCP or UDP)
- remote port or port range
- exe path of the local process
- direction: `out` (this host opened the connection) or `in` (the remote
  host opened it)

The kernel decides each TCP or UDP connection once, on its first packet. It
stores the verdict and the direction in `CONNS` (up to 65 536 connections,
the oldest are forgotten first). Later packets, replies included, use the
same verdict. Thus `default = "deny"` with an allow rule for
`direction = "out"` also allows the replies to your own connections. A rule
change makes the kernel decide every connection again. The stored state
also keeps the process that the connection was decided for, so a later
decision still knows it when the socket owner map lost the socket.

A denied inbound connection is not stored. Thus a remote host that sends
many new flows cannot push your open connections out of `CONNS`.

How a deny works:

- A new connection or UDP send fails with `Operation not permitted`. The
  cgroup `connect` and `sendmsg` hooks refuse it.
- Packets of existing connections and traffic without a local socket
  (containers, forwarded traffic) are dropped by the TC programs.
- Container and VM traffic gets its verdict where it leaves the host. On
  bridges and veth/vlan interfaces the TC programs decide only packets of
  the host: egress with a host socket, and ingress to a host address
  (`bpf_fib_lookup` says that the kernel does not forward it). A
  container's connection to the internet passes the veth and the bridge.
  The uplink egress then decides it as outbound, with the container's
  destination. A container's connection to a service on the host is
  inbound to the host.
- An exe rule follows `exec` and `fork` through the tracepoints. A program
  started through a symlink (`python3` to `python3.13`) is found by the
  `/proc` scan instead, within 10 ticks (10 s by default).

### Lockout guard

These are never blocked, whatever the rules say:

- loopback
- the SSH session that `netmon --local` started from (`SSH_CONNECTION`)
- inbound and outbound TCP on the guarded local ports: `netmond` guards
  port 22 (sshd), so that no rule can lock out a remote admin. Change it
  with `--guard-port PORT` (repeat for more ports, `0` for none).
- DNS (port 53) to the name servers in `/etc/resolv.conf`
- the DHCP and DHCPv6 client: local UDP port 68 with server port 67, local
  546 with server 547
- later fragments of TCP and UDP packets: they carry no ports, so both
  ports are 0

With `default = "deny"`, allow what the host needs. Examples are the DNS
upstream server of a local resolver (systemd-resolved) and NTP.

### Blocking from the UI

- In Connections, `b` blocks the remote address of the selected row. `B`
  blocks its remote port (TCP or UDP).
- In Processes, `b` blocks the exe of the selected process. This includes
  processes started later.
- The same key again removes the block.
- A new block goes to the top of the list. It stays until the monitor
  stops. `s` in the Rules tab saves it to the rules file.

### Rules file

At start, the monitor loads `/etc/netmon/rules.toml` or the file given with
`--rules PATH`. Rules keep the order of the file. Rules made in the UI go on
top.

```toml
# Default action for TCP and UDP traffic that no rule matches.
default = "deny"           # "allow" (the default), "deny" or "ask"

# curl can connect to HTTPS only.
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
port = "8000-8100"         # or one number; without proto: TCP and UDP

[[rule]]
action = "allow"
direction = "out"          # connections this host opens
```

- `action` is required. Each other field makes the match narrower. A rule
  with only `action` matches all traffic.
- `process` is an absolute exe path. Process names (`comm`) are refused,
  because each process can choose its own name.
- `remote` must not have host bits set. `10.1.0.0/8` is refused.
- For inbound connections, an exe rule uses the process that bound the
  local port.
- The file and its directory must belong to root and must not be writable
  by group or others. The monitor runs as root, so whoever can write the
  file controls the firewall.
- If the file has an error (unsafe owner or mode, bad TOML, bad field), the
  status line names the line and the reason. The monitor then starts
  without the rules of the file.
- `s` in the Rules tab writes all rules and the default action to the file,
  in match order. It writes a temporary file (mode 0644) and renames it
  over the old one. Only the `comment` fields stay. Other `#` comments of a
  hand-written file are lost.

### Ask mode

With `--ask` or `default = "ask"`, the monitor asks before an outbound TCP
or UDP connection that no rule decides. There is one question per program.
The question lists all waiting connections of the program by destination:

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

| Key | Answer |
|---|---|
| `←` `→` | Select the scope: `program` (any destination), `port` (this protocol and port, any host) or `destination` (this address and port) |
| `↑` `↓` | Select the destination that the `port` and `destination` scopes and `o`/`x` use |
| `a` / `d` | Allow or deny with a temporary rule for the scope (`tmp` in the Rules tab, never saved) |
| `A` / `D` | Allow or deny with a lasting rule. `s` in the Rules tab saves it. |
| `o` / `x` | Allow or deny only the waiting connections of the selected destination, without a rule |
| `Esc` / `?` | Put the questions aside, show them again |

- A rule from an answer is for outbound connections only (`out` in the
  rule line). It never opens inbound traffic, for example from source port
  53, or to the listening ports of the program.
- A new rule decides at once every waiting connection that it covers, in
  every question.
- The kernel drops the packets of a waiting connection. TCP sends its SYN
  again after about 1, 3, 7 and 15 s, so the connection goes through at
  its next try after the answer. UDP has no such retry. The first datagram
  is lost, and the next one of the program goes through.
- With no answer in 30 s, the waiting connections are denied once.
- An `o`/`x` answer and a timeout deny stay with their connections only
  while no rule decides them. A later rule or block that covers the
  connection wins, for example an allow rule after a timeout.
- More than 256 waiting connections to one destination: the extra ones
  are denied once.
- If a rule allows a connection but the kernel could not match it yet
  (the exe was not marked yet), the monitor writes the rule's verdict at
  once. The connection does not wait for a question.
- Traffic of several containers can share one question before their
  names are known. Then the question shows `several containers or
  processes`.
- Unmatched inbound connections are denied in ask mode. The lockout guard
  is never asked.
- Unknown process: traffic without a local socket (containers, VMs,
  bridges) has no program on the host. If the container tables know the
  process, the question names the container. A rule for it has no exe and
  applies to every process. Its question starts at `port` scope, because
  there is no `program` scope.
- All connected UIs show the same questions. The first answer counts.
- With no UI connected, each question times out and its connections are
  denied.
- `--once` cannot ask. Asked connections stay dropped.

## Packet capture

Select a row in Connections, Processes or Interfaces and press `Enter`.
netmon opens the Capture tab and shows:

- the packet list: number, time since start, direction (↑ out, ↓ in),
  interface, source, destination, protocol, length and a summary (TCP
  flags, sequence and acknowledgment numbers, DNS queries, ARP, ICMP)
- the decoded headers of the selected packet: Ethernet, VLAN, ARP, IPv4,
  IPv6, TCP, UDP, ICMP and DNS
- a hex and ASCII dump of the bytes

Keys: `↑` `↓` `PgUp` `PgDn` `Home` select, `End` or `f` follow new packets,
`s` save, `c` clear, `x` stop.

- A process capture follows the process. Its new connections join within
  one tick, so the first packets of a new connection (the SYN) can be
  missing.
- The kernel copies the first 1500 bytes of each packet and records the
  original length. The UI keeps up to 20 000 packets and drops the oldest.
- `s` writes `netmon-<unix time>.pcap` to the directory where you started
  `netmon`. Wireshark and `tcpdump -r` read it. The file has mode 0600 and
  belongs to you. netmon never overwrites a file and does not follow a
  symlink at that name.
- Devices without a link layer (tun, wireguard) get a dummy Ethernet header
  with zero MAC addresses. Thus all packets of a capture have one pcap link
  type.
- `ring drops` counts the packets that this capture lost because the
  kernel ring buffer (8 MiB) was full.
- `x` stops the capture and keeps the packets that the kernel already
  queued.
- One capture runs at a time. All connected UIs see it.

## The daemon

### Socket and access

`netmond` listens on `/run/netmon.sock`. The socket belongs to `root:netmon`
and has mode 0660. The daemon also identifies each client with `SO_PEERCRED`
and `SO_PEERGROUPS`: only root and members of the group can connect. If the
group does not exist, only root can connect.

Membership in group `netmon` gives full control of the firewall and of the
capture. A member can:

1. Add and remove every rule, also the rules of the rules file, and save
   them to `/etc/netmon/rules.toml`.
2. Change the default action.
3. Answer every question.
4. Capture the packets of every interface, `lo` included, and of every
   process of every user.

Thus give the group only to users who are allowed to administer the host.

The protocol is one JSON object per line (`netmon/src/proto.rs`):

1. The client sends `Hello` with the protocol version.
2. The daemon answers with `Hello` (version, tick interval, start
   messages), then a snapshot.
3. The daemon sends a snapshot after each tick and after each change,
   captured packets as base64 strings, and status messages.
4. The client sends requests: block, remove rule, save rules, answer, start
   and stop a capture. Each reply goes to the client that asked.

A request line can be 64 KiB at most. A malformed line, a second `Hello` or
a wrong version ends the connection. Up to 16 clients can connect. A slow
client never stops the monitor, and its memory has a limit:

- A new snapshot replaces a snapshot that the client did not read yet.
- Other lines (packets, replies, status) queue up to 256 lines or 16 MiB.
  Over that, the daemon drops the client.
- A client that reads nothing for 10 s is dropped.
- Requests wait in a queue of 64. A client that sends faster waits. The
  requests that wait together get one snapshot.

Pause, filter, sort and the capture view belong to each UI. Rules,
questions and the capture itself are shared.

### Stop and crash

- A clean stop (`systemctl stop netmond`, `SIGTERM`, `Ctrl-C`) removes the
  socket and all programs. No rule is in force after a clean stop.
- `systemctl restart netmond` is a clean stop and a new start. For a short
  time no rule is in force. Then the rules file loads. Rules that were not
  saved are lost.

`netmond` pins its links under `/sys/fs/bpf/netmon`: the TC links per
interface, the cgroup hooks and the tracepoints. A pinned link stays
attached when the process ends, and it keeps its program and maps. Thus if
`netmond` crashes or gets `kill -9`, the last rules stay in force:

- Blocks and the default action stay. In ask mode, nobody answers, and new
  outbound connections that no rule decides are dropped.
- Rules that were not saved also stay until the next start.
- Counting and hostnames stop, because nothing reads the maps.

systemd starts `netmond` again 2 s after a crash (`Restart=on-failure`).
The start keeps the old rules in force until the new ones are ready:

1. `netmond` makes sure that no other `netmond` runs.
2. It attaches the new programs and pins them in
   `/sys/fs/bpf/netmon-new`. The old programs stay attached. A packet then
   passes only if the old and the new programs both allow it.
3. It writes the guard, the rules file and the default action.
4. It reads the open sockets and their processes from `/proc` once. It
   writes their direction and owner to the new maps. Thus connections that
   were open before the start keep their process and their direction, and
   exe rules still apply to them.
5. It removes the old pins, and the old programs detach. Then it renames
   `netmon-new` to `netmon`.

If the rules file has an error, `netmond` stops at step 3 with exit code 78.
The old pins, and with them the old rules, stay in force. systemd does not
restart `netmond` on exit code 78 (`RestartPreventExitStatus=78`). Correct
the file, then start `netmond`. On the first start after a reboot no old
pins exist: no rule is in force until the file is correct.

On kernels before 6.6, TC programs are netlink filters and cannot be pinned.
They stay on the interface after a crash by themselves. The next start
removes them on each interface right before it attaches the new ones.

To remove the rules of a crashed daemon without a new start:

```sh
sudo rm -r /sys/fs/bpf/netmon
```

`sudo ls /sys/fs/bpf/netmon` and `sudo bpftool link list` show what is
pinned. The local mode (`netmon --local`) pins nothing. When it ends, its
rules end.

### systemd unit

`dist/netmond.service`:

- starts before `network-pre.target`, so the rules apply before the
  network comes up
- needs `/sys/fs/bpf` (`RequiresMountsFor`)
- restarts 2 s after a crash, but not after exit code 78 (error in the
  rules file)
- runs as root with only the capabilities it needs (`CAP_BPF`,
  `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`,
  `CAP_SYS_RESOURCE`, `CAP_CHOWN`, `CAP_FOWNER`). Kernels before 5.8 also
  need `CAP_SYS_ADMIN`.
- runs with `ProtectSystem=strict`. Only `/run`, `/sys/fs/bpf` and
  `/etc/netmon` (for `s` in the Rules tab) are writable.
- has a system call filter (`@system-service`, `bpf`, `perf_event_open`),
  `RestrictAddressFamilies`, `MemoryMax=1G`, `TasksMax=64` and the other
  `Protect*` and `Restrict*` settings in the file.

The log is in the journal: `journalctl -u netmond`.

### Profiling

`NETMON_PROFILE=1` makes `netmond` (or `netmon --local`) write the CPU use
and the time of each step of the monitor loop to stderr every 30 s.

## Decisions

This section lists the design decisions and their reasons. `docs/REVIEW.md`
has the review that started the firewall work. `docs/ROADMAP.md` has the
phases and the commits.

### eBPF with aya, Linux only

netmon must see every packet and every socket call, at the moment they
happen. eBPF does this without a kernel module. aya lets the kernel
programs and the user space program share one language (Rust) and one set
of types (`netmon-common`).

### TC programs for packets, cgroup hooks for sockets

TC programs see every packet on every interface, also forwarded and
container traffic. They do not know the process. The cgroup socket hooks
know the process and see each `connect` and `sendmsg` before a packet
exists. netmon uses both. The hooks give the owner and refuse new
connections early. TC counts bytes and drops what has no socket. Kprobes
were not used, because they need kernel structure offsets (CO-RE) that aya
does not give in a stable way.

### Pass to the next program

An allowed packet returns `TC_ACT_UNSPEC`, not `TC_ACT_OK`. Under tcx,
`TC_ACT_OK` ends the chain, and tools attached after netmon (Cilium,
other monitors) then never run.

### Owner identity is the exe path, not the process name

Any process can set its own name with `prctl`. A rule therefore names an
exe path, which comes from `/proc/<pid>/exe`. The kernel gives each exe a
number (`EXE_IDS`) and marks each process that runs it (`TGID_EXE`). The
exec, new-task and exit tracepoints keep the marks current. Exe numbers are never
used again, so an old mark can never point to another exe.

### Owner sources, best first

The kernel hooks give the owner of most connections at their first packet.
`/proc` is the fallback for sockets that existed before netmon started. A
weaker source never replaces a stronger one. The section [Owners](#owners)
lists them.

### One verdict per connection

The kernel decides a connection on its first packet and stores the verdict
in an LRU map. Later packets do not walk the rules again. Replies use the
same verdict. This makes "allow out, deny in" possible without connection
tracking in netfilter. A rule change makes the kernel decide each
connection again. A generation number in `RULE_CFG` marks old verdicts.

### Ordered rule table, written in two halves

The kernel walks up to 256 rules with `bpf_loop`. A plain loop over 256
rules was too large for the verifier (1 million instructions). The table has
two halves. The monitor writes the new rules into the inactive half and then
switches one number. The kernel therefore never sees a half-written table.

### Fail-open for errors, lockout guard always

A packet that the parser cannot read passes, with one exception: an IPv6
packet whose upper header the parser did not reach gets the default action
of TCP and UDP. Otherwise a long chain of extension headers would pass
every rule. The lockout guard (loopback, the SSH port and session, DNS to
the system resolver, the DHCP client) is never blocked. A wrong rule
therefore never cuts the remote session that is needed to fix it.

### Rules survive a daemon crash, a clean stop removes them

A firewall that disappears with a crash protects nothing. `netmond` pins
its links, so the last rules stay after a crash, and systemd restarts it.
A clean stop removes them, because the administrator asked for it. The
local mode (`sudo netmon --local`) stays fail-open: it is for a quick look,
not for protection.

### Ask mode drops the first packet

The kernel cannot hold a packet while a person thinks. netmon drops the
packets of an asked connection and relies on TCP retransmits, which come
after about 1, 3, 7 and 15 s. The first UDP datagram is lost. NFQUEUE holds
packets, but it leaves eBPF and needs netfilter. It can come later.

### One question per program

A browser opens many connections at start. One question per connection gave
about 200 questions. netmon groups the waiting connections by program and by
destination. The answer then covers the whole program, one port, one
destination, or only the waiting connections.

### Daemon and unprivileged UI

The UI parses untrusted data (packets, DNS, process names) and draws it. It
must not run as root. `netmond` keeps everything that needs root.
Packet decoding and pcap writing run in the UI. The UI therefore gets raw
bytes and writes files as your user.

### JSON lines over a Unix socket

JSON lines are easy to read, test and debug. Captured packets travel as
base64. A binary format can come later if capture throughput needs it. The
socket file mode and `SO_PEERCRED` give two independent access checks.

### Hostnames from the kernel, not from reverse DNS

Reverse DNS often gives a CDN name or no name. netmon reads the DNS answers
that the host itself received and the SNI of each TLS connection. These are
the names that the programs asked for. No extra DNS traffic is sent.

### Containers from their network namespaces

A container connection has no socket on the host. netmon finds the
container processes through `/proc/*/ns/net` and reads their socket tables
from `/proc/<pid>/net/*`. A read takes about 400 ms on a host with many
containers, so a background thread does it, and only when a new connection
has no owner.

### Count each byte once

Traffic crosses veth, bridge and uplink. The totals and the graph count
only physical interfaces. The Connections and Processes tabs hide rows of
bridges and veth or vlan interfaces until you press `v`.

### CPU use

The monitor reads `/proc` as little as possible. It reads `/proc/*/fd` only
for sockets that the kernel hooks did not name, and at most every 2 s. The
exe scan runs every 10 ticks while the tracepoints run. On a host with 3630
processes and many containers in ask mode, `netmond` uses about 16 % of one
core. Most of this is container table reads. `docs/ROADMAP.md` has the plan
to read them with netlink `sock_diag`.

## Limits

### Owners

The detail line under the Connections table names the source of the owner.
The sources, best first:

1. `kernel`: the process that created the flow's own socket, or connected
   or sent on it.
2. `/proc`: the process that holds the socket with the exact addresses.
3. `kernel (bind)`: the process that bound the local address (servers, UDP
   receivers). Accepted connections have no connect hook, so they get this
   source when `/proc` is too late.
4. `container /proc`: a socket in a container namespace.
5. `/proc (port)`: a guess by local port.

Limits of the `/proc` sources:

- A socket that opens and closes between two ticks (a DNS query, a short
  `curl`) without a kernel owner shows `?`.
- Container sockets: on veth and bridge interfaces the match is exact
  (state `container`). On the uplink after masquerade, the match is by
  remote end and local port (state `nat`). This fails when NAT changed the
  port. A new container connection gets its owner within about 10 s.
- Rules cannot name a container, because its packets have no socket on the
  host. Ask mode names the container, but its rules have no exe.
- Listeners and unconnected UDP sockets match by port and bound address. A
  process that binds a port gets the traffic of that port.
- A socket shared after `fork` shows the first process found that holds it.
- The process name (`comm`) is not proof of identity. Use the exe path,
  the user and the unit in the detail line.

### Counting

- Traffic that crosses several interfaces shows once per interface. The
  totals count physical interfaces only. VPN traffic counts as its
  encrypted packets on the uplink.
- Forwarded traffic (router, bridge) shows as if the host sent it: on
  egress, the source counts as local.
- netmon follows up to 2 VLAN tags and 6 IPv6 extension headers.
  Fragments after the first count with port 0 and pass. An IPv6 packet
  with more headers counts with the last header type as its protocol and
  gets the default action of TCP and UDP.
- Interface totals count from the start of the monitor, not from boot.

### Firewall

- A connection that `CONNS` forgot while it was open (map full) is decided
  again on its next packet. It can then count as opened by the other side.
  Denied inbound flows do not fill the map, but allowed ones (for example
  many new connections to a public server port) do.
- If the map of marked processes is full (8192 processes of exes that
  rules name), the status line says so, and the exe rules do not apply to
  the processes that did not fit.
- Only TCP and UDP get the default action. ICMP and other protocols pass.
- An exe started through a symlink or a relative path is marked by the
  `/proc` scan, so it can connect for up to 10 ticks before its rule
  applies.
- Exe rules do not stop an attacker who runs with the same user id: a copy
  of the binary, `LD_PRELOAD` or ptrace get around them. They control
  programs that cooperate.

## Development

### Layout

| Path | Content |
|---|---|
| `netmon-ebpf/` | Kernel programs (`no_std`): TC, cgroup hooks, tracepoints |
| `netmon-common/` | Types that kernel and user space share, the packet parser, the rule match |
| `netmon/src/monitor.rs` | The monitor: owners, rules, hostnames, questions, capture |
| `netmon/src/engine.rs` | The monitor on its clock: ticks and polls |
| `netmon/src/daemon.rs` | `netmond`: socket, peer check, clients |
| `netmon/src/tui.rs`, `client.rs`, `remote.rs` | The UI: terminal loop, snapshot view, daemon connection |
| `netmon/src/proto.rs` | Wire types: requests, snapshots, packets |
| `netmon/src/ui.rs`, `app.rs` | Drawing and UI state |
| `netmon/src/probe.rs` | Loads and attaches the eBPF programs, reads the maps, pins the links |
| `dist/netmond.service` | systemd unit |
| `docs/ROADMAP.md`, `docs/REVIEW.md` | Phases, review and decisions |

### Tests

The tests run without root and without the eBPF build:

```sh
AYA_BUILD_SKIP=1 cargo test
AYA_BUILD_SKIP=1 cargo clippy --all-targets
```

A binary built with `AYA_BUILD_SKIP=1` has no eBPF object and refuses to
run. Tests of the monitor use a fake kernel (`Fake` in
`netmon/src/monitor.rs`).

For a change to the kernel programs, run `cargo build --release` and read
the object with `llvm-objdump`. Make sure that:

- no instruction uses `r11`. A function with more than 5 arguments spills
  into it, and the verifier refuses the program.
- the stack of each program, with its subprograms, fits in 512 bytes.
- the cgroup hooks return only 0 or 1.

### Without the daemon and without sudo

The local mode can run without sudo through file capabilities. Use the
daemon instead where you can.

| Capability | Why |
|---|---|
| `cap_bpf` | load programs, create maps |
| `cap_net_admin` | attach TC programs, add `clsact` |
| `cap_perfmon` | attach tracepoints, fewer verifier limits |
| `cap_sys_ptrace` | read `/proc/<pid>/fd` links of other users' processes |
| `cap_dac_read_search` | list `/proc/<pid>/fd` of other users' processes |

Do not set these capabilities on a file in `target/` or in a directory that
your user can write. Each person who can run the binary can read every
packet on the host. A rebuild removes the capabilities, and a writable file
can be replaced. Install a root-owned copy that only one group can run:

```sh
sudo install -o root -g netmon -m 0750 target/release/netmon /usr/local/bin/netmon-local
sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_sys_ptrace,cap_dac_read_search+ep /usr/local/bin/netmon-local
netmon-local --local
```

This capability set comes from the kernel checks. It was not tested
without root.
