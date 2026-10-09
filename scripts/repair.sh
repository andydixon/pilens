#!/bin/bash
# Re-establish permissions, capabilities and services without touching data or the
# applied network configuration.   sudo ./repair.sh
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
ok() { echo "  ✓ $*"; }; bad() { echo "  ✗ $*"; }

echo "Repairing PiLens"
id pilens >/dev/null 2>&1 || { useradd --system --home-dir /var/lib/pilens --no-create-home --shell /usr/sbin/nologin pilens; ok "recreated user pilens"; }
usermod -aG wireshark pilens && ok "pilens in group wireshark"
install -d -o pilens -g pilens -m 0750 /var/lib/pilens && ok "/var/lib/pilens ownership"
chown -R pilens:pilens /var/lib/pilens
install -d -o root -g root -m 0700 /var/lib/pilens-helper && ok "/var/lib/pilens-helper ownership"

if ! getcap /usr/bin/dumpcap 2>/dev/null | grep -q cap_net_raw; then
  echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
  DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive wireshark-common >/dev/null 2>&1
fi
getcap /usr/bin/dumpcap | grep -q cap_net_raw && ok "dumpcap capture capabilities" || bad "dumpcap lacks capabilities"

systemctl daemon-reload
systemctl enable pilens-firewall pilens-helper pilens-dnsmasq pilens >/dev/null 2>&1
systemctl reset-failed 'pilens*' 2>/dev/null
systemctl restart pilens-firewall && ok "firewall table restored from last good configuration" || bad "pilens-firewall failed"
systemctl restart pilens-helper && ok "helper restarted" || bad "helper failed"
[ -f /var/lib/pilens-helper/dnsmasq.conf ] && { systemctl restart pilens-dnsmasq && ok "DHCP/DNS restarted" || bad "pilens-dnsmasq failed"; }
if nmcli -g GENERAL.STATE connection show pilens-ap 2>/dev/null | grep -q activated; then ok "access point active"
elif nmcli connection show pilens-ap >/dev/null 2>&1; then nmcli connection up pilens-ap >/dev/null 2>&1 && ok "access point re-activated" || bad "access point failed to start (check: journalctl -u NetworkManager)"; fi
systemctl restart pilens && sleep 3
curl -fsk --max-time 3 https://127.0.0.1:8443/api/health >/dev/null && ok "web service healthy" || bad "web service unhealthy: journalctl -u pilens -n 50"
echo
echo "If the administrator password is lost: sudo -u pilens /opt/pilens/bin/pilens reset-password -user <name>"
