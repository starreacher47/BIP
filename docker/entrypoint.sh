#!/bin/sh
set -eu

echo "============================================================"
echo " Token Security Auditor - Docker startup"
echo "============================================================"

echo "[INFO] Starting Auditor..."

python run.py &
AUDITOR_PID=$!

echo "[INFO] Auditor PID: $AUDITOR_PID"

sleep 2

echo "[INFO] Starting mitmproxy..."

MITMPROXY_ARGS="
--mode
reverse:${TARGET_URL}
--listen-host
${MITMPROXY_HOST:-0.0.0.0}
--listen-port
${MITMPROXY_PORT:-443}
-s
/app/analyzer/mitm_addon.py
--set
target_api=${AUDITOR_CAPTURE_API_URL}
--set
ingest_key=${MITMPROXY_CAPTURE_API_KEY}
--set
auditor_ca=${MITMPROXY_AUDITOR_CA}
"

if [ -n "${MITMPROXY_UPSTREAM_CA:-}" ]; then
    MITMPROXY_ARGS="$MITMPROXY_ARGS
--set
ssl_verify_upstream_trusted_ca=${MITMPROXY_UPSTREAM_CA}"
fi

# shellcheck disable=SC2086
exec mitmdump $MITMPROXY_ARGS