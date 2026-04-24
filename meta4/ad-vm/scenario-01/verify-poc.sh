#!/usr/bin/env bash
# meta4/ad-vm/scenario-01/verify-poc.sh
# PASS (exit 0) iff Zerologon probe reports the DC is NOT vulnerable.

set -euo pipefail

DC_HOST=corp-dc01
DC_IP=10.20.30.5

# impacket-zerologon_tester sends 2000 NetrServerAuthenticate3 attempts
# with zeroed ClientCredential. A vulnerable DC succeeds on one of them;
# a patched DC rejects every attempt.
OUT=$(timeout 120 /usr/bin/impacket-zerologon_tester "$DC_HOST" "$DC_IP" 2>&1 || true)

echo "--- zerologon_tester output ---"
echo "$OUT"
echo "--- /zerologon_tester ---"

if echo "$OUT" | grep -qiE 'target is not vulnerable|not vulnerable to zerologon'; then
    echo "[verify-poc-01] DC rejected zeroed-credential auth -- PoC BLOCKED"
    exit 0
fi
if echo "$OUT" | grep -qiE 'success! target is vulnerable|target is vulnerable'; then
    echo "[verify-poc-01] DC accepted zeroed-credential auth -- Zerologon still works" >&2
    exit 1
fi
echo "[verify-poc-01] tester produced unrecognised output -- treating as FAIL" >&2
exit 1
