#!/bin/bash
# fetch_log.sh - Download and filter slp-trace.log from Switch
# Usage: ./fetch_log.sh [filter_pattern]

set -e

SWITCH_IP="10.172.227.168"
SWITCH_PORT="5000"
FTP_BASE="ftp://${SWITCH_IP}:${SWITCH_PORT}"
LOCAL_LOG="/tmp/slp-trace-$(date +%Y%m%d-%H%M%S).log"

echo "Downloading slp-trace.log from Switch..."
curl -s "${FTP_BASE}/slp-trace.log" -o "${LOCAL_LOG}" 2>/dev/null

if [ ! -s "${LOCAL_LOG}" ]; then
    echo "Failed to download log or log is empty"
    exit 1
fi

echo "Downloaded to ${LOCAL_LOG} ($(wc -l < "${LOCAL_LOG}") lines)"

FILTER="${1:-lan|browse|port 30000|fd=2|F_DUPFD|DUPFD|tracked|proxy}"

echo "Filtering for: ${FILTER}"
grep -i -E "${FILTER}" "${LOCAL_LOG}" | tail -50

echo ""
echo "Full log: ${LOCAL_LOG}"