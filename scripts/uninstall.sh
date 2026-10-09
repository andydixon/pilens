#!/bin/bash
# Remove PiLens. Captures and settings in /var/lib/pilens are KEPT unless --purge.
#   sudo ./uninstall.sh [--purge] [--yes]
set -euo pipefail
PURGE=0; YES=0
for a in "$@"; do case "$a" in --purge) PURGE=1 ;; --yes|-y) YES=1 ;; *) echo "unknown option $a"; exit 2 ;; esac; done
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
confirm() { [ "$YES" = 1 ] && return 0; read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]; }

echo "This removes the PiLens services, the 'pilens-ap' access-point profile, the 'inet pilens' firewall table and /opt/pilens."
[ $PURGE = 1 ] && echo "--purge: ALSO deletes /var/lib/pilens: every capture, setting and account."
confirm "Continue?" || exit 1
if [ $PURGE = 1 ]; then
  read -r -p "Type DELETE to permanently delete all captures: " x
  [ "$x" = DELETE ] || { echo "not confirmed; keeping data"; PURGE=0; }
fi

systemctl disable --now pilens pilens-dnsmasq pilens-helper pilens-firewall 2>/dev/null || true
nmcli connection delete pilens-ap 2>/dev/null && echo "removed access-point profile (other Wi-Fi profiles were never modified and will reconnect)" || true
rm -f /etc/NetworkManager/system-connections/pilens-ap.nmconnection
nft delete table inet pilens 2>/dev/null && echo "removed firewall table inet pilens" || true
echo "note: IPv4 forwarding was left as it is now ($(sysctl -n net.ipv4.ip_forward)); other services may depend on it"
rm -f /etc/systemd/system/pilens*.service
systemctl daemon-reload
rm -rf /opt/pilens /var/lib/pilens-helper /run/pilens
if [ $PURGE = 1 ]; then
  rm -rf /var/lib/pilens
  userdel pilens 2>/dev/null || true
  echo "data purged"
else
  echo "kept /var/lib/pilens (captures, database). Remove it with: sudo rm -rf /var/lib/pilens"
fi
echo "apt packages (tshark, wireshark-common, nftables, dnsmasq-base, iw) were left installed."
echo "Configuration backups are in /var/backups/pilens/."
