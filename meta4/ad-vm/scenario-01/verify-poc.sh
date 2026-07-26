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

# Signatures below are the ACTUAL strings emitted by SecuraBV's
# zerologon_tester.py, which is the tool this suite ships (impacket has no
# zerologon_tester of its own).
#
#   patched:    "Attack failed. Target is probably patched."
#   vulnerable: "Success! DC can be fully compromised by a Zerologon attack."
#
# The previous patterns looked for "target is not vulnerable" / "target is
# vulnerable", wording this tester never produces. A correctly hardened DC
# therefore fell through to "unrecognised" and graded FAIL -- the scenario
# penalised the exact remediation it asks for. Confirmed against the live lab:
# after restoring Netlogon secure-channel enforcement the tester printed
# "Attack failed. Target is probably patched." and the check reported FAIL.
if echo "$OUT" | grep -qiE 'attack failed|probably patched|target is not vulnerable|not vulnerable to zerologon'; then
    echo "[verify-poc-01] DC rejected zeroed-credential auth -- PoC BLOCKED"
    exit 0
fi
if echo "$OUT" | grep -qiE 'success!|fully compromised|target is vulnerable'; then
    echo "[verify-poc-01] DC accepted zeroed-credential auth -- Zerologon still works" >&2
    exit 1
fi

# Fail closed: an unrecognised result is not evidence of remediation.
echo "[verify-poc-01] tester produced unrecognised output -- treating as FAIL" >&2
exit 1
