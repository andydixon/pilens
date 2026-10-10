#!/bin/bash
# Collect a diagnostic bundle. Secrets (Wi-Fi passphrase, setup token, keys,
# sessions, captured packets) are excluded or redacted by default.
#   sudo ./diagnose.sh            -> /tmp/pilens-diagnose-<time>.tar.gz
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
TS=$(date +%Y%m%d-%H%M%S)
D=$(mktemp -d /tmp/pilens-diagnose-XXXX)
chmod 700 "$D"
run() { local f="$D/$1"; shift; { echo "\$ $*"; "$@"; } >"$f" 2>&1 || true; }
redact() { sed -E 's/("passphrase"[[:space:]]*:[[:space:]]*")[^"]*/\1REDACTED/g; s/^(psk=).*/\1REDACTED/; s/(setup_token=).*/\1REDACTED/'; }

run versions.txt sh -c 'cat /opt/pilens/VERSION; uname -a; cat /etc/os-release; tr -d "\0" </proc/device-tree/model; echo; tshark --version | head -1; nmcli --version; dnsmasq --version | head -1; nft --version'
run services.txt systemctl status --no-pager pilens pilens-helper pilens-firewall pilens-dnsmasq pilens-proxy NetworkManager
run journal.txt journalctl --no-pager -n 3000 -u pilens -u pilens-helper -u pilens-firewall -u pilens-dnsmasq
run journal-nm.txt journalctl --no-pager -n 800 -u NetworkManager
run nft-pilens.txt nft list table inet pilens
run nft-tables.txt nft list tables
run ip.txt sh -c 'ip -br link; ip addr; ip route; ip -6 route; sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding'
run nm.txt sh -c 'nmcli general; nmcli device; nmcli connection show'
run nm-pilens-ap.txt nmcli connection show pilens-ap
run wifi.txt sh -c 'iw dev; iw reg get; iw list'
run interception.txt sh -c 'ls -la /var/lib/pilens/proxy 2>/dev/null; echo; [ -f /var/lib/pilens/proxy/ca/mitmproxy-ca-cert.pem ] && openssl x509 -in /var/lib/pilens/proxy/ca/mitmproxy-ca-cert.pem -noout -subject -fingerprint -sha256 -dates; /opt/pilens/proxy-venv/bin/mitmdump --version 2>/dev/null | head -1'
run capture.txt sh -c 'getcap /usr/bin/dumpcap; id pilens; ls -la /var/lib/pilens /var/lib/pilens-helper'
run resources.txt sh -c 'df -h; free -m; uptime; vcgencmd get_throttled; vcgencmd measure_temp; timedatectl'
cp /var/lib/pilens-helper/dnsmasq.conf "$D/dnsmasq.conf" 2>/dev/null
redact </var/lib/pilens-helper/last-good.json >"$D/network-config.json" 2>/dev/null
redact <"$D/nm-pilens-ap.txt" >"$D/x" && mv "$D/x" "$D/nm-pilens-ap.txt"
for f in "$D"/*; do redact <"$f" >"$f.r" && mv "$f.r" "$f"; done

OUT=/tmp/pilens-diagnose-$TS.tar.gz
tar -C "$D" -czf "$OUT" . && chmod 600 "$OUT"
rm -rf "$D"
echo "diagnostic bundle: $OUT"
echo "Excluded: database, captures, TLS keys, setup token. Review the bundle before you share it."
