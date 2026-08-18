#!/usr/bin/env bash
# Run the spike suites against a FRESH slp-server-rust instance.
#
# Always starts on a new port so a stale long-running server (whose
# IP->sockaddr cache may have dead entries from a previous run) cannot
# skew results. See notes/spike-results.md for the stale-map quirk.
#
# Usage: tools/run-spike.sh [port]
set -euo pipefail

PORT="${1:-11552}"
SERVER_BIN="$HOME/switch/slp-server-rust/target/release/slp-server-rust"
SPIKE_DIR="$(cd "$(dirname "$0")/../spike" && pwd)"

echo "== starting fresh slp-server-rust on :$PORT =="
"$SERVER_BIN" -p "$PORT" >"/tmp/slp-spike-$PORT.log" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT
sleep 1

echo "== M1 protocol spike (slp_spike) =="
python3 "$SPIKE_DIR/slp_spike.py" "$PORT"

echo
echo "== LAN-mode suite (test_lan) =="
python3 "$SPIKE_DIR/test_lan.py" 127.0.0.1 "$PORT"

echo
echo "== LDN control-plane suite (test_ldn) =="
python3 "$SPIKE_DIR/test_ldn.py" 127.0.0.1 "$PORT"

echo
echo "server log (/tmp/slp-spike-$PORT.log):"
sed -n '1,20p' "/tmp/slp-spike-$PORT.log"
