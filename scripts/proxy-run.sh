#!/bin/bash
# Launches mitmdump for PiLens interception from the core-written env file.
# Runs as the unprivileged 'pilens' user under the pilens-proxy.service unit.
set -eu
ENV=/var/lib/pilens/proxy/proxy.env
[ -f "$ENV" ] || { echo "no proxy.env; interception not configured" >&2; exit 1; }
. "$ENV"
export PILENS_FLOWS PILENS_BODIES PILENS_CAPTURE_BODIES PILENS_MAX_BODY_KB
args=( --mode transparent --listen-host 0.0.0.0 --listen-port "$PILENS_PROXY_PORT"
       --set "confdir=$PILENS_CONFDIR" --set block_global=false --set connection_strategy=lazy
       --set stream_large_bodies=1m -s "$PILENS_ADDON" -q )
if [ -n "${PILENS_IGNORE:-}" ]; then args+=( --ignore-hosts "$PILENS_IGNORE" ); fi
exec "$PILENS_VENV/bin/mitmdump" "${args[@]}"
