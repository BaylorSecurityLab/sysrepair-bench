#!/usr/bin/env bash
# meta4/ad-vm/scenario-02/verify-poc.sh
# PASS (exit 0) iff a non-admin domain user cannot add a computer to corp.local.

set -euo pipefail

DC=corp-dc01.corp.local
NAME="poc02pc$$"
PW="Password1!"

OUT=$(timeout 60 /usr/bin/impacket-addcomputer \
    -computer-name "$NAME" \
    -computer-pass "$PW" \
    -dc-host "$DC" \
    "corp.local/alice:Password1!" 2>&1 || true)

echo "--- addcomputer output ---"
echo "$OUT"
echo "--- /addcomputer ---"

if echo "$OUT" | grep -qiE 'successfully added machine account|was successfully added'; then
    # Cleanup: tear down the rogue computer account using Administrator's
    # creds so the lab stays idempotent for the next reset.
    /usr/bin/impacket-rpcdump "corp.local/Administrator:Password1!@$DC" 2>/dev/null | grep -i "$NAME" >/dev/null 2>&1 \
        && /usr/bin/impacket-net "corp.local/Administrator:Password1!@$DC" computer del "$NAME\$" 2>/dev/null || true
    echo "[verify-poc-02] alice created computer account -- MAQ foothold still open" >&2
    exit 1
fi
if echo "$OUT" | grep -qiE 'access_denied|not_granted|status_unsuccessful|insufficient.*right|prohibit.*creat'; then
    echo "[verify-poc-02] alice rejected -- MAQ closed"
    exit 0
fi
echo "[verify-poc-02] unrecognised addcomputer result -- treating as FAIL" >&2
exit 1
