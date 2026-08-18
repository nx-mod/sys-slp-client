#!/bin/bash
# clear_logs.sh - Wipe all sys-slp-client logs + crash dumps before a fresh test run.
#
# Clears:
#   1. Server log            /tmp/slp-server.log              (server killed first)
#   2. Demo host log         /tmp/slp-demo-host.log           (demo host killed first)
#   3. PC client log         /tmp/slp-pc-client.log           (client killed first)
#   4. Stale local traces    /tmp/slp-trace-*.log
#   5. Switch trace          /slp-trace.log            (DELE'd via FTP; sysmodule re-creates on next write)
#   6. Switch crash dumps    /atmosphere/fatal_reports/dumps/, /atmosphere/erpt_reports/, /atmosphere/crash_reports/dumps/
#                                                                                    (DELE'd via FTP)
#
# Then restarts the relay server + demo host + PC client with fresh logs so the box is test-ready.
#
# Usage: ./clear_logs.sh

set -u

SWITCH_IP="10.172.227.168"
SWITCH_PORT="5000"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAN_PLAY_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RELAY_BIN="${LAN_PLAY_ROOT}/slp-server-rust/target/release/slp-server-rust.exe"
DEMO_HOST="python3 -u ${LAN_PLAY_ROOT}/sys-slp-client/spike/demo_host.py 127.0.0.1 11451"
PC_CLIENT_BIN="${LAN_PLAY_ROOT}/switch-lan-play/build/src/Debug/lan-play.exe"
PC_CLIENT_ARGS="--relay-server-addr 127.0.0.1:11451 --netif Wi-Fi"

# NOTE: pkill in this shell can't see processes started from a different
# session context (e.g. PowerShell Start-Process) -- it silently no-ops
# instead of erroring, which looks like success but isn't. taskkill reaches
# them regardless of how they were launched.
echo "== Killing server + demo host + PC client (releases log fds) =="
taskkill //F //IM slp-server-rust.exe >/dev/null 2>&1
taskkill //F //IM lan-play.exe >/dev/null 2>&1
for pid in $(tasklist //FI "IMAGENAME eq python.exe" //FO CSV 2>/dev/null | tail -n +2 | cut -d',' -f2 | tr -d '"'); do
    taskkill //F //PID "${pid}" >/dev/null 2>&1
done
sleep 1

echo "== Clearing server + demo host + PC client logs and stale local traces =="
rm -f /tmp/slp-server.log /tmp/slp-demo-host.log /tmp/slp-pc-client.log
rm -f /tmp/slp-trace-*.log
rm -f /tmp/report_*.bin /tmp/fatal_*.bin

echo "== Clearing Switch trace + crash dumps (FTP) =="
python3 - "${SWITCH_IP}" "${SWITCH_PORT}" <<'PY'
import ftplib, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    ftp = ftplib.FTP(); ftp.connect(host, port, timeout=15); ftp.login()
except Exception as e:
    print(f"  WARN: FTP connect failed: {e}"); sys.exit(0)

try:
    ftp.delete("slp-trace.log")
    print("  slp-trace.log deleted")
except Exception as e:
    print(f"  slp-trace.log: already gone ({e})")

for d in ("atmosphere/fatal_reports/dumps", "atmosphere/erpt_reports",
          "atmosphere/crash_reports/dumps"):
    try:
        names = [n for n, _ in ftp.mlsd(d) if n not in (".", "..") and "/" not in n]
    except Exception as e:
        print(f"  {d}: absent")
        continue
    for n in names:
        try:
            ftp.delete(f"{d}/{n}")
            print(f"  deleted crash dump {d}/{n}")
        except Exception as e:
            print(f"  WARN: DELE {d}/{n} failed: {e}")
    print(f"  {d}: {len(names)} dump(s) removed")
ftp.quit()
PY

echo "== Restarting relay with fresh log =="
nohup "${RELAY_BIN}" -p 11451 > /tmp/slp-server.log 2>&1 &
RELAY_PID=$!
sleep 1
if kill -0 "${RELAY_PID}" 2>/dev/null; then
    echo "  relay up (PID ${RELAY_PID}) -> /tmp/slp-server.log"
else
    echo "  WARN: relay failed to start"
fi

echo "== Restarting demo host with fresh log =="
nohup ${DEMO_HOST} > /tmp/slp-demo-host.log 2>&1 &
DEMO_PID=$!
sleep 2
if kill -0 "${DEMO_PID}" 2>/dev/null; then
    echo "  demo host up (PID ${DEMO_PID}) -> /tmp/slp-demo-host.log"
else
    echo "  WARN: demo host failed to start"
fi

echo "== Restarting PC client with fresh log =="
if [ -x "${PC_CLIENT_BIN}" ]; then
    nohup "${PC_CLIENT_BIN}" ${PC_CLIENT_ARGS} > /tmp/slp-pc-client.log 2>&1 &
    CLIENT_PID=$!
    sleep 2
    if kill -0 "${CLIENT_PID}" 2>/dev/null; then
        echo "  PC client up (PID ${CLIENT_PID}) -> /tmp/slp-pc-client.log"
    else
        echo "  WARN: PC client failed to start"
    fi
else
    echo "  WARN: PC client binary not found at ${PC_CLIENT_BIN}, skipping"
fi

echo ""
echo "All logs + crash dumps cleared. Ready for a fresh test."
