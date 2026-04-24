#!/usr/bin/env bash
# meta4/ad-vm/scenario-06/verify-poc.sh
# PASS (exit 0) iff alice cannot DCSync the krbtgt hash from the DC.

set -euo pipefail

OUT=$(timeout 90 /usr/bin/impacket-secretsdump \
    -just-dc-ntlm \
    -just-dc-user 'krbtgt' \
    'corp.local/alice:Password1!@corp-dc01.corp.local' 2>&1 || true)

echo "--- secretsdump output ---"
echo "$OUT"
echo "--- /secretsdump ---"

if echo "$OUT" | grep -qE '^krbtgt:[0-9]+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::'; then
    echo "[verify-poc-06] alice successfully DCSync'd krbtgt -- non-admin replication still allowed" >&2
    exit 1
fi
if echo "$OUT" | grep -qiE 'access_denied|rpc_s_access_denied|dssync.*failed|permission.*denied'; then
    echo "[verify-poc-06] DCSync denied for alice -- PoC BLOCKED"
    exit 0
fi
echo "[verify-poc-06] unrecognised secretsdump result -- treating as FAIL" >&2
exit 1
