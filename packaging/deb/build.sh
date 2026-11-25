#!/bin/sh
# Builds a .deb of netmon from this repository (Debian, Ubuntu).
# Needs: the Rust toolchain of the README (nightly with rust-src,
# bpf-linker) and dpkg-deb.
#
# Usage: packaging/deb/build.sh [--no-build]
#   --no-build  uses the binaries in target/release as they are.
# Output: target/debian/netmon_VERSION_ARCH.deb
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"

if [ "${1:-}" != "--no-build" ]; then
    cargo build --release --locked
fi

version=$(sed -n 's/^version = "\(.*\)"/\1/p' netmon/Cargo.toml | head -n1)
case $(uname -m) in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *) arch=$(uname -m) ;;
esac
root="$repo/target/debian/netmon_${version}_${arch}"
rm -rf "$root"
mkdir -p "$root/DEBIAN"
sh packaging/install-tree.sh "$repo" "$root"

cat > "$root/DEBIAN/control" <<EOF
Package: netmon
Version: $version
Architecture: $arch
Maintainer: netmon contributors
Depends: libc6, systemd
Recommends: libnotify-bin, curl
Section: net
Priority: optional
Homepage: https://github.com/chilimatic/netmon
Description: eBPF network monitor and per-program firewall with a terminal UI
 netmond loads eBPF programs that count traffic per connection and program
 and enforce firewall rules per executable. netmon is the terminal UI.
EOF

cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
    systemd-sysusers netmon.conf >/dev/null 2>&1 || getent group netmon >/dev/null || addgroup --system netmon
    systemctl daemon-reload >/dev/null 2>&1 || true
    echo "netmon: add your user to the group netmon, then: sudo systemctl enable --now netmond"
fi
EOF

cat > "$root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ]; then
    systemctl disable --now netmond.service >/dev/null 2>&1 || true
fi
EOF

cat > "$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
EOF
chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "dpkg-deb not found: the package tree is in $root" >&2
    exit 1
fi
dpkg-deb --root-owner-group --build "$root" "$repo/target/debian/"
