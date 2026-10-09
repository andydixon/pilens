#!/bin/bash
# PiLens benchmark. Drives the running appliance over its own API and measures
# capture throughput, loss, filter latency, dissection latency, export and import.
# Numbers are hardware-dependent; this prints exactly what it measured.
#
#   ./benchmark.sh https://127.0.0.1:8443 admin <<<"$PASSWORD"
#   (reads the admin password from stdin so it never appears in argv or history)
set -euo pipefail
BASE=${1:-https://127.0.0.1:8443}
USER=${2:-admin}
read -r PASS
J=$(mktemp); trap 'rm -f "$J" /tmp/pilens-bench.*' EXIT
CJ() { curl -sk -b "$J" -c "$J" -H 'X-Requested-With: pilens' -H "X-CSRF-Token: ${CSRF:-}" -H 'Content-Type: application/json' "$@"; }
now() { date +%s.%N; }
# arithmetic/formatting via python3 (no bc/numfmt dependency)
calc() { python3 -c "import sys;print(eval(sys.argv[1]))" "$1"; }
iec() { python3 -c "
import re
m=re.search(r'\\d+','$1' or '0'); n=float(m.group() if m else 0)
for u in ['B','KiB','MiB','GiB','TiB']:
  if abs(n)<1024: print('%.1f %s'%(n,u)); break
  n/=1024
else: print('%.1f PiB'%n)"; }
CSRF=$(CJ -X POST "$BASE/api/auth/login" -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["csrf"])')
jq() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)"; }

MB=${BENCH_MB:-300}
echo "# PiLens benchmark $(date -Is)"
echo "host: $(tr -d '\0' </proc/device-tree/model 2>/dev/null) · $(nproc) cores · $(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo)"
MEM0=$(systemctl show -p MemoryCurrent --value pilens 2>/dev/null || echo 0)
echo "idle pilens RSS: $(iec ${MEM0:-0})"

# ---- capture throughput on loopback under a bulk transfer ----
head -c $((MB*1000000)) /dev/urandom >/tmp/pilens-bench.bin
python3 -m http.server 8998 --bind 127.0.0.1 --directory /tmp >/dev/null 2>&1 & SRV=$!
sleep 1
SID=$(CJ -X POST "$BASE/api/captures" -d '{"name":"benchmark","interfaces":["lo"],"capture_filter":"tcp port 8998"}' | jq 'd["id"]')
t0=$(now)
for i in $(seq 1 ${BENCH_LOOPS:-4}); do curl -s -o /dev/null "http://127.0.0.1:8998/pilens-bench.bin" 2>/dev/null || true; done
t1=$(now)
sleep 2
CJ -X POST "$BASE/api/captures/live/stop" >/dev/null
kill $SRV 2>/dev/null || true
S=$(CJ "$BASE/api/captures/$SID")
PK=$(echo "$S" | jq 'd["session"]["packets"]'); BY=$(echo "$S" | jq 'd["session"]["bytes"]')
DROPS=$(echo "$S" | jq 'd["session"].get("drops","")')
secs=$(calc "$t1 - $t0")
echo
echo "## capture (loopback, $MB MB x ${BENCH_LOOPS:-4} transfers)"
printf "  packets: %s   bytes: %s   wall: %.1fs\n" "$PK" "$(iec $BY)" "$secs"
printf "  rate: %.0f pkt/s   %.0f MB/s\n" "$(calc "$PK/$secs")" "$(calc "$BY/$secs/1000000")"
echo "  drops: $DROPS"
MEM1=$(systemctl show -p MemoryCurrent --value pilens); echo "  pilens RSS after capture: $(iec $MEM1)"

# ---- display filter latency over the whole capture ----
echo
echo "## display filter latency (cold, tshark over all segments)"
for F in "tcp" "tcp.port==8998" "tcp.analysis.retransmission" "frame.len>1000"; do
  t0=$(now); TOT=$(CJ "$BASE/api/captures/$SID/packets?filter=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$F")&limit=1" | jq 'd["total"]'); t1=$(now)
  printf "  %-32s %6s matches  %.2fs\n" "$F" "$TOT" "$(calc "$t1-$t0")"
done

# ---- packet dissection latency ----
echo
echo "## packet detail (PDML dissection)"
MIDN=$(CJ "$BASE/api/captures/$SID/packets?offset=$((PK/2))&limit=1" | jq 'd["rows"][0]["n"]')
t0=$(now); CJ "$BASE/api/captures/$SID/packets/$MIDN" >/dev/null; t1=$(now)
printf "  single packet #%s: %.3fs\n" "$MIDN" "$(calc "$t1-$t0")"

# ---- export ----
echo
echo "## export (verbatim copy of original packets)"
t0=$(now); CJ -o /tmp/pilens-bench.out "$BASE/api/captures/$SID/export"; t1=$(now)
SZ=$(stat -c%s /tmp/pilens-bench.out); printf "  %s in %.2fs (%.0f MB/s)\n" "$(iec $SZ)" "$(calc "$t1-$t0")" "$(calc "$SZ/($t1-$t0)/1000000")"

# ---- import + index ----
echo
echo "## import + full index of that file"
t0=$(now); ISID=$(CJ -H 'Content-Type: application/octet-stream' --data-binary @/tmp/pilens-bench.out "$BASE/api/captures/import?name=bench-import" | jq 'd["id"]')
while [ "$(CJ "$BASE/api/captures/$ISID" | jq 'd["session"]["state"]')" = importing ]; do sleep 0.3; done
t1=$(now)
IPK=$(CJ "$BASE/api/captures/$ISID" | jq 'd["session"]["packets"]')
printf "  indexed %s packets in %.1fs (%.0f pkt/s)\n" "$IPK" "$(calc "$t1-$t0")" "$(calc "$IPK/($t1-$t0)")"

echo
echo "cleanup: removing benchmark sessions"
CJ -X DELETE "$BASE/api/captures/$SID?confirm=$SID" >/dev/null
CJ -X DELETE "$BASE/api/captures/$ISID?confirm=$ISID" >/dev/null
echo "done"
