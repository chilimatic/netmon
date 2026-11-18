# netmon

Terminal UI that shows open network connections, the process that owns each
one, the interface it uses, and live upload/download rates. Linux only.

## How it works

- eBPF TC programs (`netmon-ebpf`) run on ingress and egress of every
  interface. They parse IPv4/IPv6 + TCP/UDP headers and count bytes and
  packets per flow and interface in an LRU per-CPU hash map.
- Userspace (`netmon`) reads the map every second, computes rates, and maps
  each flow to a process with `/proc/net/{tcp,udp}{,6}` and `/proc/<pid>/fd`.
- New interfaces (containers, VPNs) are attached automatically every 2 s.

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

Root or capabilities are needed to load eBPF programs:

```sh
sudo ./target/release/netmon
# or
sudo setcap cap_bpf,cap_net_admin,cap_perfmon,cap_sys_ptrace,cap_dac_read_search+ep target/release/netmon
./target/release/netmon
```

Without the TUI: `netmon --once 3` samples 3 s and prints a table.

Keys: `←`/`→` (or `Tab`, `1-4`) switch view, `Esc` clear filter, `Enter` capture the selected row, `r`/`t`/`n` sort by rate/total/name, `/` filter,
`p` pause, `g` toggle the traffic graph, `↑↓` select, `q` quit.

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
- "ring drops" counts packets lost because the kernel ring buffer (8 MiB)
  filled faster than the UI read it.

## Limits

- Owners come from `/proc`, so very short-lived processes and sockets in
  other network namespaces (containers) can show as `?`.
- Traffic that crosses several interfaces (veth, bridge, uplink) is counted
  once per interface. The header total skips `lo` but still counts that.
- IPv6 extension headers are not followed; such packets have port 0.
