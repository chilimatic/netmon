#!/bin/sh
# Installs the built netmon files into a staging directory, as a package
# needs them: binaries in /usr/bin, units in /usr/lib/systemd, the group in
# sysusers.d. The PKGBUILD and the .deb build use it.
#
# Usage: packaging/install-tree.sh REPO_DIR STAGING_DIR
set -eu
src=$1
dest=$2
rel="$src/target/release"

install -Dm0755 "$rel/netmond" "$dest/usr/bin/netmond"
install -Dm0755 "$rel/netmon" "$dest/usr/bin/netmon"
install -Dm0755 "$rel/netmon-notify" "$dest/usr/bin/netmon-notify"
install -Dm0755 "$rel/netmon-blocklist-update" "$dest/usr/bin/netmon-blocklist-update"
install -Dm0755 "$src/dist/netmon-geoip-update" "$dest/usr/bin/netmon-geoip-update"

# The units in dist/ name /usr/local/bin (a manual install).
for unit in netmond.service netmon-geoip.service netmon-geoip.timer netmon-blocklists.service netmon-blocklists.timer; do
    sed 's|/usr/local/bin/|/usr/bin/|g' "$src/dist/$unit" > "$dest/tmp-unit"
    install -Dm0644 "$dest/tmp-unit" "$dest/usr/lib/systemd/system/$unit"
done
sed 's|/usr/local/bin/|/usr/bin/|g' "$src/dist/netmon-notify.service" > "$dest/tmp-unit"
install -Dm0644 "$dest/tmp-unit" "$dest/usr/lib/systemd/user/netmon-notify.service"
rm -f "$dest/tmp-unit"

install -Dm0644 "$src/packaging/netmon.sysusers" "$dest/usr/lib/sysusers.d/netmon.conf"
install -Dm0644 "$src/docs/rules.example.toml" "$dest/usr/share/doc/netmon/rules.example.toml"
install -Dm0644 "$src/README.md" "$dest/usr/share/doc/netmon/README.md"
install -dm0755 "$dest/etc/netmon"
