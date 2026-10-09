#!/bin/bash
# PiLens installer / upgrader.
#   sudo ./install.sh                                   interactive
#   sudo ./install.sh --non-interactive --config setup.yaml
# Options: --mgmt-iface IF  --mgmt-subnet CIDR[,CIDR]  --yes  --allow-unsupported
#
# This script does NOT reconfigure any existing network connection. The access
# point is created later, by the setup wizard (or --config), through the helper's
# transactional apply with automatic rollback.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
PREFIX=/opt/pilens
DATA=/var/lib/pilens
LOG=/var/log/pilens-install.log
NONINT=0; CONFIG=""; YES=0; ALLOW=0; MGMT_IF=""; MGMT_NET=""

while [ $# -gt 0 ]; do
  case "$1" in
    --non-interactive) NONINT=1; YES=1 ;;
    --config) CONFIG="$2"; shift ;;
    --yes|-y) YES=1 ;;
    --allow-unsupported) ALLOW=1 ;;
    --mgmt-iface) MGMT_IF="$2"; shift ;;
    --mgmt-subnet) MGMT_NET="$2"; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
  shift
done

c_b=$'\e[1m'; c_y=$'\e[33m'; c_r=$'\e[31m'; c_g=$'\e[32m'; c_0=$'\e[0m'
say()  { echo "${c_b}==>${c_0} $*"; echo "[$(date -Is)] $*" >>"$LOG"; }
warn() { echo "${c_y}warning:${c_0} $*"; echo "[$(date -Is)] WARN $*" >>"$LOG"; }
die()  { echo "${c_r}error:${c_0} $*" >&2; echo "[$(date -Is)] ERROR $*" >>"$LOG"; exit 1; }
confirm() { [ "$YES" = 1 ] && return 0; read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]; }

[ "$(id -u)" = 0 ] || die "run as root: sudo $0"
[ -x "$SRC/bin/pilens" ] && [ -x "$SRC/bin/pilens-helper" ] || die "binaries not found in $SRC/bin (run from the extracted release package)"
touch "$LOG"; chmod 600 "$LOG"

# ---------------------------------------------------------------- 1. platform
say "Checking platform"
. /etc/os-release
ARCH=$(uname -m)
SUPPORTED=1
[ "$ARCH" = aarch64 ] || { warn "architecture $ARCH (expected aarch64)"; SUPPORTED=0; }
case "${VERSION_CODENAME:-}" in bookworm|trixie) ;; *) warn "OS ${PRETTY_NAME:-unknown} is not a tested Raspberry Pi OS / Debian release"; SUPPORTED=0 ;; esac
[ $SUPPORTED = 1 ] || [ $ALLOW = 1 ] || die "unsupported platform (use --allow-unsupported to continue anyway)"
MODEL=$(tr -d '\0' </proc/device-tree/model 2>/dev/null || echo "unknown")
echo "    ${PRETTY_NAME} · ${ARCH} · ${MODEL}"
systemctl is-active --quiet NetworkManager || die "NetworkManager is not running. PiLens requires NetworkManager (default on Raspberry Pi OS Bookworm and later)."
echo "    NetworkManager $(nmcli --version | awk '{print $NF}')"

# ---------------------------------------------------------------- 2. interfaces and management
say "Detecting interfaces"
UPLINK=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
SSH_IP=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
SSH_LOCAL=$(echo "${SSH_CONNECTION:-}" | awk '{print $3}')
SSH_IF=""
[ -n "$SSH_LOCAL" ] && SSH_IF=$(ip -o -4 addr show | awk -v a="$SSH_LOCAL" '{split($4,x,"/"); if(x[1]==a) print $2}')
WIFI=$(for d in /sys/class/net/*; do [ -d "$d/wireless" ] || [ -e "$d/phy80211" ] && basename "$d"; done | head -1 || true)
ip -br addr | grep -v '^lo' | sed 's/^/    /'
echo "    default route: ${UPLINK:-none}   wifi: ${WIFI:-none}   your SSH session: ${SSH_IP:-local console}${SSH_IF:+ via $SSH_IF}"

if [ -n "$SSH_IF" ] && [ "$SSH_IF" = "$WIFI" ]; then
  warn "your SSH session arrives over $WIFI. That interface becomes the access point in the setup wizard, which will disconnect this session."
  warn "reconnect over Ethernet before running the wizard. Management must use a wired interface."
  MGMT_IF=${MGMT_IF:-$UPLINK}
fi
MGMT_IF=${MGMT_IF:-${SSH_IF:-$UPLINK}}
[ -n "$MGMT_IF" ] || die "could not determine a management interface; pass --mgmt-iface"
[ "$MGMT_IF" != "$WIFI" ] || die "the management interface cannot be the Wi-Fi interface"
if [ -z "$MGMT_NET" ]; then
  MGMT_NET=$(ip -o -4 route show dev "$MGMT_IF" scope link proto kernel | awk '{print $1}' | head -1)
  # A NATed or routed admin source outside the local subnet must be allowed explicitly.
  if [ -n "$SSH_IP" ] && ! python3 -c "import ipaddress,sys; sys.exit(0 if ipaddress.ip_address('$SSH_IP') in ipaddress.ip_network('$MGMT_NET') else 1)" 2>/dev/null; then
    MGMT_NET="$MGMT_NET,$SSH_IP/32"
  fi
fi
echo "    management: interface ${c_b}$MGMT_IF${c_0}, allowed sources ${c_b}$MGMT_NET${c_0}"
echo "    (a wired network is not trusted just because it is wired; narrow this with --mgmt-subnet)"

# ---------------------------------------------------------------- 3-5. capabilities, resources, conflicts
say "Checking Wi-Fi, resources and conflicts"
if command -v iw >/dev/null && [ -n "$WIFI" ]; then
  iw list 2>/dev/null | awk '/Supported interface modes/{f=1;next} f&&/^\t\t\*/{print} f&&!/^\t\t\*/{f=0}' | grep -q '\* AP$' && echo "    AP mode supported" || warn "Wi-Fi radio does not report AP mode support"
elif [ -z "$WIFI" ]; then warn "no Wi-Fi interface found; the access point cannot be configured"; fi
FREE_MB=$(df -Pm / | awk 'NR==2{print $4}'); MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
echo "    free disk ${FREE_MB} MiB, memory ${MEM_MB} MiB"
[ "$FREE_MB" -ge 1024 ] || die "at least 1 GiB free disk space is required"
[ "$MEM_MB" -ge 900 ] || warn "less than 1 GiB RAM: large captures and dissection will be slow"
for s in dnsmasq hostapd isc-dhcp-server udhcpd; do
  systemctl is-active --quiet "$s" 2>/dev/null && warn "$s.service is running and may conflict with PiLens DHCP/DNS on the AP interface"
done
systemctl is-enabled --quiet nftables 2>/dev/null && grep -q 'flush ruleset' /etc/nftables.conf 2>/dev/null && \
  warn "nftables.service is enabled and /etc/nftables.conf flushes the whole ruleset. pilens-firewall is ordered after it, but reloading nftables manually will remove the PiLens table until 'sudo systemctl restart pilens-firewall'."

UPGRADE=0; [ -x "$PREFIX/bin/pilens" ] && UPGRADE=1

# ---------------------------------------------------------------- 6. explain
echo
if [ $UPGRADE = 1 ]; then
  say "Existing installation found ($(cat $PREFIX/VERSION 2>/dev/null || echo unknown)); this will UPGRADE to $(cat "$SRC/VERSION")."
  echo "    Data in $DATA (captures, settings, accounts) is kept."
else
  cat <<EOF
${c_b}This will:${c_0}
  • apt install: tshark wireshark-common nftables dnsmasq-base iw (dumpcap capture rights for group 'wireshark')
  • create system user 'pilens' (no login), add it to group 'wireshark'
  • install binaries and docs in $PREFIX, data in $DATA, systemd units in /etc/systemd/system
  • start pilens-firewall, pilens-helper, pilens (the web UI on port 8443, $MGMT_IF only)
  • back up NetworkManager profiles and the current nftables ruleset to /var/backups/pilens/

${c_b}It will not:${c_0} change any existing network connection, touch other firewall tables,
  or enable IP forwarding. The access point is created later, in the setup wizard.
EOF
fi
confirm "Proceed?" || die "aborted by user"

# ---------------------------------------------------------------- 7. backup
TS=$(date +%Y%m%d-%H%M%S)
BK=/var/backups/pilens/$TS
say "Backing up configuration to $BK"
mkdir -p "$BK"; chmod 700 /var/backups/pilens "$BK"
cp -a /etc/NetworkManager/system-connections "$BK/" 2>/dev/null || true
nft list ruleset >"$BK/nft-ruleset.txt" 2>/dev/null || true
sysctl -n net.ipv4.ip_forward >"$BK/ip_forward" 2>/dev/null || true
cp -a /etc/systemd/system/pilens*.service "$BK/" 2>/dev/null || true
[ -d "$PREFIX" ] && cp -a "$PREFIX" "$BK/opt-pilens" || true

ROLLBACK=1
rollback() {
  [ "${ROLLBACK:-0}" = 1 ] || return 0
  echo; warn "installation failed; rolling back (log: $LOG)"
  if [ $UPGRADE = 1 ] && [ -d "$BK/opt-pilens" ]; then
    rm -rf "$PREFIX"; cp -a "$BK/opt-pilens" "$PREFIX"
    cp -a "$BK"/pilens*.service /etc/systemd/system/ 2>/dev/null || true
    systemctl daemon-reload; systemctl restart pilens-helper pilens 2>/dev/null || true
    warn "previous version restored"
  else
    systemctl disable --now pilens pilens-helper pilens-firewall pilens-dnsmasq 2>/dev/null || true
    rm -f /etc/systemd/system/pilens*.service; systemctl daemon-reload
    rm -rf "$PREFIX"
    warn "PiLens services removed. Installed apt packages were left in place: they are harmless when unused."
  fi
}
trap rollback EXIT

# ---------------------------------------------------------------- 8. packages
say "Installing packages"
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >>"$LOG" 2>&1 || warn "apt-get update failed; trying with cached package lists"
apt-get install -y -qq --no-install-recommends tshark wireshark-common nftables dnsmasq-base iw ca-certificates >>"$LOG" 2>&1 || die "apt-get install failed (see $LOG)"
dpkg-reconfigure -f noninteractive wireshark-common >>"$LOG" 2>&1 || true
getcap /usr/bin/dumpcap | grep -q cap_net_raw || die "dumpcap has no capture capabilities after install (getcap /usr/bin/dumpcap)"
# dnsmasq-base must not bring a competing system dnsmasq service.
systemctl is-enabled --quiet dnsmasq 2>/dev/null && warn "dnsmasq.service (full package) is enabled. Disable it, or make sure it does not listen on the AP interface."

# ---------------------------------------------------------------- 9-12. files, user, units
say "Installing PiLens $(cat "$SRC/VERSION")"
getent group pilens >/dev/null || groupadd --system pilens
id pilens >/dev/null 2>&1 || useradd --system --gid pilens --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin pilens
usermod -aG wireshark pilens
systemctl stop pilens 2>/dev/null || true
mkdir -p "$PREFIX"
install -m 0755 "$SRC/bin/pilens" "$SRC/bin/pilens-helper" -D -t "$PREFIX/bin"
for f in install.sh uninstall.sh repair.sh diagnose.sh setup.example.yaml VERSION README.md LICENSE; do install -m 0644 "$SRC/$f" "$PREFIX/$f"; done
chmod 0755 "$PREFIX"/*.sh
rm -rf "$PREFIX/docs"; cp -r "$SRC/docs" "$PREFIX/docs"
install -d -o pilens -g pilens -m 0750 "$DATA"
install -d -o root -g root -m 0700 /var/lib/pilens-helper
install -m 0644 "$SRC"/systemd/*.service /etc/systemd/system/
systemctl daemon-reload

# ---------------------------------------------------------------- 15. initialise data
say "Initialising database and management certificate"
INIT=$(runuser -u pilens -- "$PREFIX/bin/pilens" init -data "$DATA" -mgmt-iface "$MGMT_IF" -mgmt-subnet "$MGMT_NET")
FP=$(echo "$INIT" | sed -n 's/^certificate_sha256=//p')
TOKEN=$(echo "$INIT" | sed -n 's/^setup_token=//p')

# ---------------------------------------------------------------- 18. enable and start
say "Starting services"
systemctl enable pilens-firewall pilens-helper pilens-dnsmasq pilens >>"$LOG" 2>&1
systemctl restart pilens-firewall pilens-helper
systemctl restart pilens

# ---------------------------------------------------------------- 19. health
say "Verifying service health"
for i in $(seq 1 30); do
  curl -fsk --max-time 2 https://127.0.0.1:8443/api/health >/dev/null 2>&1 && break
  sleep 1
done
curl -fsk --max-time 2 https://127.0.0.1:8443/api/health >/dev/null || { journalctl -u pilens -n 30 --no-pager; die "pilens did not become healthy"; }
[ -S /run/pilens/helper.sock ] || die "helper socket missing (journalctl -u pilens-helper)"
echo "    ${c_g}pilens and pilens-helper are healthy${c_0}"
ROLLBACK=0
trap - EXIT

if [ -n "$CONFIG" ]; then
  say "Applying non-interactive configuration from $CONFIG"
  TMPC=$(mktemp -p "$DATA" setup.XXXXXX.yaml); install -o pilens -m 0600 "$CONFIG" "$TMPC"
  if ! runuser -u pilens -- "$PREFIX/bin/pilens" setup -data "$DATA" -config "$TMPC"; then rm -f "$TMPC"; die "non-interactive setup failed; the network configuration was rolled back"; fi
  rm -f "$TMPC"
  warn "delete $CONFIG if it contains a plaintext password"
  TOKEN=""
fi

MIP=$(ip -o -4 addr show dev "$MGMT_IF" | awk '{split($4,a,"/"); print a[1]; exit}')
echo
echo "${c_g}${c_b}PiLens $(cat "$SRC/VERSION") installed.${c_0}"
echo "  Open:            ${c_b}https://${MIP}:8443/${c_0}   (from $MGMT_NET)"
echo "  Certificate:     SHA-256 $FP"
echo "                   Your browser will warn that the certificate is self-signed. Check that this fingerprint matches before you continue."
[ -n "$TOKEN" ] && echo "  Setup token:     ${c_b}$TOKEN${c_0}   (needed once, in the setup wizard)"
echo "  Logs:            journalctl -u pilens -u pilens-helper -u pilens-dnsmasq"
echo "  Backup:          $BK"
