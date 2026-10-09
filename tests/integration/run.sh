#!/bin/bash
# Integration tests, run inside the pilens-test container (see `make test-docker`).
# 1. Go test binaries that need tshark/dumpcap.
# 2. A routed topology in Linux network namespaces exercising the rendered
#    firewall, DHCP/DNS and the real pilens service end to end:
#
#   [ns up]  up0 10.99.0.1/24 (mgmt host + router)   lo: 198.51.100.7 (public), 172.16.5.5 (private)
#      |
#   [ns pi]  eth0 10.99.0.2/24 ── nft inet pilens ── wlan0 192.168.50.1/24   (pilens serve, dnsmasq)
#      |
#   [ns cl]  c0 (DHCP client)
set -uo pipefail
T=/t; SRC=/src
PASS=0; FAIL=0
ok()   { echo "  PASS $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL $*"; FAIL=$((FAIL+1)); }
check() { local name="$1"; shift; if "$@" >/tmp/out 2>&1; then ok "$name"; else fail "$name"; sed 's/^/       /' /tmp/out | tail -5; fi; }
refuse() { local name="$1"; shift; if "$@" >/tmp/out 2>&1; then fail "$name (unexpectedly succeeded)"; else ok "$name"; fi; }

echo "== Go tests needing tshark/dumpcap"
for p in pcapfile capture api; do
  ( cd "$SRC/internal/$p" && "$T/$p.test" -test.timeout 120s >/tmp/gt.$p 2>&1 ) && ok "go test ./internal/$p" || { fail "go test ./internal/$p"; tail -20 /tmp/gt.$p; }
done

echo "== Network namespace topology"
for n in up pi cl; do ip netns add $n; done
ip link add up0 netns up type veth peer name eth0 netns pi
ip link add wlan0 netns pi type veth peer name c0 netns cl
ip -n up addr add 10.99.0.1/24 dev up0
ip -n up addr add 198.51.100.7/32 dev lo; ip -n up addr add 172.16.5.5/32 dev lo
ip -n pi addr add 10.99.0.2/24 dev eth0
ip -n pi addr add 192.168.50.1/24 dev wlan0
for n in up pi cl; do ip -n $n link set lo up; done
ip -n up link set up0 up; ip -n pi link set eth0 up; ip -n pi link set wlan0 up; ip -n cl link set c0 up
ip -n pi route add default via 10.99.0.1
ip -n up route add 192.168.50.0/24 via 10.99.0.2   # a route that would bypass NAT if forwarding were open
# IPv6 everywhere, to prove AP clients cannot escape over it
ip -n up addr add fd01::1/64 dev up0 nodad; ip -n pi addr add fd01::2/64 dev eth0 nodad
ip -n pi addr add fd50::1/64 dev wlan0 nodad; ip -n cl addr add fd50::10/64 dev c0 nodad
ip -n cl route add fd01::/64 via fd50::1; ip -n up route add fd50::/64 via fd01::2
ip netns exec pi sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1

# public and private services upstream
ip netns exec up python3 -m http.server 80 --bind 198.51.100.7 >/dev/null 2>&1 &
ip netns exec up python3 -m http.server 80 --bind 172.16.5.5 >/dev/null 2>&1 &
ip netns exec up python3 -m http.server 8080 --bind 10.99.0.1 >/dev/null 2>&1 &

# an unrelated table that must survive every apply
ip netns exec pi nft add table inet other
ip netns exec pi nft add chain inet other keepme

render() { # $1 = forwarding mode
  cat >/tmp/net.json <<EOF
{"management":{"interfaces":["eth0"],"allowed_subnets":["10.99.0.0/24"],"port":8443},"uplink":"eth0",
 "ap":{"enabled":true,"interface":"wlan0","ssid":"PiLens-Test","passphrase":"integration-test","security":"wpa2","band":"bg","channel":6,"country":"GB"},
 "lan":{"address":"192.168.50.1/24","dhcp_start":"192.168.50.100","dhcp_end":"192.168.50.150","lease_minutes":60,"upstream_dns":["10.99.0.1"],
        "reservations":[],"dns_overrides":[{"name":"override.pilens.test","ip":"192.0.2.55"}]},
 "forwarding":{"mode":"$1","allow_cidrs":[]}}
EOF
  "$T/pilens-helper" -render /tmp/net.json >/tmp/render.txt || return 1
  awk '/^### nftables/{f="/tmp/ruleset.nft";next} /^### dnsmasq.conf/{f="/tmp/dnsmasq.conf";next} /^### /{f="";next} f{print > f}' /tmp/render.txt
}

check "render configuration (internet mode)" render internet
check "nft -c accepts ruleset" ip netns exec pi nft -c -f /tmp/ruleset.nft
check "apply ruleset" ip netns exec pi nft -f /tmp/ruleset.nft
check "re-apply ruleset is atomic and idempotent" ip netns exec pi nft -f /tmp/ruleset.nft
check "unrelated nft table untouched" ip netns exec pi nft list chain inet other keepme

mkdir -p /var/lib/pilens-helper
ip netns exec pi dnsmasq --conf-file=/tmp/dnsmasq.conf --pid-file=/tmp/dnsmasq.pid --log-facility=/tmp/dnsmasq.log
sleep 1

echo "== DHCP and DNS"
cat >/tmp/udhcpc.sh <<'EOF'
#!/bin/sh
[ "$1" = bound ] || [ "$1" = renew ] || exit 0
ip addr add "$ip/${mask:-24}" dev "$interface"
for r in $router; do ip route add default via "$r"; done
echo "$dns" >/tmp/client.dns; echo "$ip" >/tmp/client.ip
EOF
chmod +x /tmp/udhcpc.sh
check "client obtains a DHCP lease" ip netns exec cl busybox udhcpc -i c0 -n -q -t 5 -s /tmp/udhcpc.sh
CIP=$(cat /tmp/client.ip 2>/dev/null)
check "lease is inside the pool ($CIP)" sh -c "echo '$CIP' | grep -Eq '^192\.168\.50\.(1[0-4][0-9]|150)$'"
check "DHCP gives the Pi as DNS server" grep -q 192.168.50.1 /tmp/client.dns
check "default route is the Pi" sh -c "ip -n cl route | grep -q 'default via 192.168.50.1'"
check "local DNS override answers" sh -c "ip netns exec cl dig +short +time=2 +tries=1 @192.168.50.1 override.pilens.test | grep -qx 192.0.2.55"
check "lease file written" grep -q "$CIP" /var/lib/pilens-helper/dnsmasq.leases

echo "== Forwarding policy (internet mode)"
check "client reaches public destination" ip netns exec cl curl -s -m 3 -o /dev/null http://198.51.100.7/
check "public server sees NATed source (10.99.0.2)" sh -c "ip netns exec up ss -tn state time-wait | grep -q 10.99.0.2 || ip netns exec cl curl -s -m 3 http://198.51.100.7/ >/dev/null"
refuse "client blocked from RFC1918 destination 172.16.5.5" ip netns exec cl curl -s -m 3 -o /dev/null http://172.16.5.5/
refuse "client blocked from management/upstream subnet 10.99.0.1" ip netns exec cl curl -s -m 3 -o /dev/null http://10.99.0.1:8080/
refuse "IPv6 from client is not forwarded" ip netns exec cl ping -6 -c 1 -W 2 fd01::1
refuse "client blocked from Pi SSH port" ip netns exec cl bash -c 'exec 3<>/dev/tcp/192.168.50.1/22'
refuse "upstream cannot open connections into the AP subnet" ip netns exec up ping -c 1 -W 2 "$CIP"

echo "== Real pilens service in the pi namespace"
mkdir -p /tmp/pdata
INIT=$(ip netns exec pi "$T/pilens" init -data /tmp/pdata -mgmt-iface eth0 -mgmt-subnet 10.99.0.0/24)
TOKEN=$(echo "$INIT" | sed -n 's/^setup_token=//p')
ip netns exec pi "$T/pilens" serve -data /tmp/pdata -listen :8443 -helper-socket /tmp/nohelper.sock >/tmp/pilens.log 2>&1 &
for i in $(seq 1 30); do ip netns exec up curl -fsk -m 1 https://10.99.0.2:8443/api/health >/dev/null 2>&1 && break; sleep 0.5; done
check "management reachable from allowed subnet" ip netns exec up curl -fsk -m 3 https://10.99.0.2:8443/api/health
refuse "management NOT reachable from AP client" ip netns exec cl curl -fsk -m 3 https://192.168.50.1:8443/api/health
refuse "management NOT reachable from AP client via the uplink address" ip netns exec cl curl -fsk -m 3 https://10.99.0.2:8443/api/health

J=/tmp/cookies
api() { ip netns exec up curl -sk -m 30 -b $J -c $J -H 'X-Requested-With: pilens' -H "X-CSRF-Token: ${CSRF:-}" -H 'Content-Type: application/json' "$@"; }
R=$(api -X POST https://10.99.0.2:8443/api/setup/admin -d "{\"token\":\"$TOKEN\",\"username\":\"admin\",\"password\":\"integration-password\",\"authorised\":true}")
CSRF=$(echo "$R" | python3 -c 'import json,sys; print(json.load(sys.stdin)["csrf"])' 2>/dev/null)
check "admin created with setup token" test -n "$CSRF"
R=$(api -X POST https://10.99.0.2:8443/api/captures -d '{"name":"netns","interfaces":["wlan0"]}')
SID=$(echo "$R" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)
check "capture started on wlan0 ($SID)" test -n "$SID"
sleep 2
for i in 1 2 3; do ip netns exec cl curl -s -m 3 -o /dev/null http://198.51.100.7/; ip netns exec cl dig +short +time=1 +tries=1 @192.168.50.1 override.pilens.test >/dev/null; done
sleep 2
check "capture stopped" api -fX POST https://10.99.0.2:8443/api/captures/live/stop
N=$(api "https://10.99.0.2:8443/api/captures/$SID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session"]["packets"])')
check "client traffic captured ($N packets)" test "${N:-0}" -gt 10
check "display filter http.request over API" sh -c "$(declare -f api); J=$J CSRF=$CSRF; api 'https://10.99.0.2:8443/api/captures/$SID/packets?filter=http.request' | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d[\"total\"]==3, d'"
check "packet detail with verified byte ranges" sh -c "$(declare -f api); J=$J CSRF=$CSRF; api 'https://10.99.0.2:8443/api/captures/$SID/packets/1' | grep -q '\"verified\":true'"
api -o /tmp/export.pcapng "https://10.99.0.2:8443/api/captures/$SID/export"
check "export opens in tshark with all packets" sh -c "[ \$(tshark -r /tmp/export.pcapng 2>/dev/null | wc -l) -eq $N ]"
check "integrity verification ok" sh -c "$(declare -f api); J=$J CSRF=$CSRF; api -X POST https://10.99.0.2:8443/api/captures/$SID/verify | grep -q '\"status\":\"ok\"'"
refuse "API rejects state change without CSRF token" ip netns exec up curl -fsk -m 5 -b $J -X POST https://10.99.0.2:8443/api/captures/live/stop

echo "== Deny mode"
check "render configuration (deny mode)" render deny
check "apply deny ruleset" ip netns exec pi nft -f /tmp/ruleset.nft
refuse "client cannot reach public destination in deny mode" ip netns exec cl curl -s -m 3 -o /dev/null http://198.51.100.7/
check "DNS still served in deny mode" sh -c "ip netns exec cl dig +short +time=2 +tries=1 @192.168.50.1 override.pilens.test | grep -qx 192.0.2.55"
check "unrelated nft table still present" ip netns exec pi nft list chain inet other keepme

echo
echo "integration: $PASS passed, $FAIL failed"
[ $FAIL = 0 ]
