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
- New interfaces (containers, VPNs) are found and attached every second
  refresh interval.

## Requirements

- Linux 5.11 or later. Tested only on 6.18; older kernels are supported by
  design, not yet by test.
  - 6.6 and later: programs attach with tcx and run next to other tc/tcx
    programs.
  - Before 6.6: netmon adds a `clsact` qdisc to each interface (if missing)
    and attaches with netlink. The qdisc stays after netmon exits; remove it
    with `tc qdisc del dev <iface> clsact` if nothing else uses it.
  - 5.8 to 5.10 count eBPF memory against `RLIMIT_MEMLOCK`. Loading fails
    unless the limit is raised first, e.g. `ulimit -l unlimited` in a root
    shell. Older kernels have no ring buffer and are not supported.
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

netmon loads eBPF programs and reads every process's sockets, so it runs as
root:

```sh
sudo ./target/release/netmon
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

Keys: `←`/`→` (or `Tab`, `1-4`) switch view, `Esc` clear filter, `Enter` capture the selected row, `r`/`t`/`n` sort by rate/total/name, `/` filter,
`p` pause the view (counting goes on), `g` toggle the traffic graph, `↑↓` select, `q` quit.

The graph on top shows total traffic of all interfaces except `lo` for the
last 120 samples: download above the zero line, upload below. Each half has
its own scale (shown on the y axis).

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
- Only sockets in netmon's own network namespace are visible. Container
  traffic on `veth` and bridge interfaces shows as `?`.
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

- Traffic that crosses several interfaces (veth, bridge, uplink) is counted
  once per interface. The header total skips `lo` but counts the rest.
- Forwarded traffic (router, bridge) is shown as if the host sent it: on
  egress the source is taken as local.
- IPv6 extension headers are not followed; such packets count with port 0.
- Interface totals count from netmon's start, not from boot.
