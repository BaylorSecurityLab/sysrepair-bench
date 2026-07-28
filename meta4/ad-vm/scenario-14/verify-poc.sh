#!/usr/bin/env bash
# meta4/ad-vm/scenario-14/verify-poc.sh
# PASS (exit 0) iff the DC REFUSES an NTLMv1 session setup.
#
# REWRITTEN AROUND A CALIBRATED DISCRIMINATOR. Two things were wrong before.
#
# 1. THE VERDICT MATCHED ITS OWN COMMAND LINE. The "remediated" branch grepped
#    smbclient's -d 5 debug output for /NTLMv2/i -- while the invocation itself
#    passed `--option='client ntlmv2 auth=no'`, which is echoed back in that
#    debug stream. So the check matched its own argument and reported
#    "DC enforced NTLMv2 -- BLOCKED" on a fully vulnerable DC, failing gate 1
#    on the 2026-07-27 run. Same family as scenario-17's "Using unpatched
#    function" and scenario-19's "Authentication only": a string that describes
#    what was REQUESTED, mistaken for what was ANSWERED.
#
# 2. RESPONDER WAS NEVER NEEDED. The scenario started a Responder listener and
#    then never made the DC authenticate to it -- smbclient authenticates TO
#    the DC, so the listener could only ever observe silence. Dropping it also
#    removes the `sudo` dependency the image does not ship and the interface
#    detection that needed `ip`, which the image does not ship either.
#
# What this scenario actually asks is whether the DC still accepts an NTLMv1
# response, which is answered by trying exactly that.
#
# Calibrated against the live DC in both states:
#
#   LmCompatibilityLevel=2 (injected)   NTLMv1 -> connects
#   LmCompatibilityLevel=5 (remediated) NTLMv1 -> NT_STATUS_LOGON_FAILURE
#
# An NTLMv2 attempt runs as a CONTROL. Without it, a DC that is simply down
# would fail the NTLMv1 probe and read as remediated; requiring the control to
# succeed means only a DC that is up and answering can produce a verdict.

set -uo pipefail

DC=10.20.30.5
USER='corp\alice%Password1!'

if ! command -v smbclient >/dev/null 2>&1; then
    echo "[verify-poc-14] HARNESS ERROR: smbclient not present on the attacker" >&2
    exit 2
fi

# --- NTLMv1 forced ---
V1=$(timeout 45 smbclient -L "//$DC" -U "$USER" \
        --option='client lanman auth=yes' \
        --option='client ntlmv2 auth=no' \
        --option='client min protocol=NT1' 2>&1)
V1_RC=$?

# --- NTLMv2 control ---
V2=$(timeout 45 smbclient -L "//$DC" -U "$USER" 2>&1)
V2_RC=$?

echo "--- NTLMv1-forced session setup (rc=$V1_RC) ---"
echo "$V1" | tail -6
echo "--- NTLMv2 control (rc=$V2_RC) ---"
echo "$V2" | tail -4
echo "--- /probes ---"

if [ "$V1_RC" -eq 124 ] || [ "$V2_RC" -eq 124 ]; then
    echo "[verify-poc-14] HARNESS ERROR: SMB probe timed out" >&2
    exit 2
fi

# --- the control must succeed, or nothing can be concluded ---
# A refused NTLMv1 only means something if the DC is otherwise answering this
# same user over SMB.
if [ "$V2_RC" -ne 0 ]; then
    echo "[verify-poc-14] HARNESS ERROR: the NTLMv2 control also failed" >&2
    echo "[verify-poc-14] the DC is not answering SMB for this account, so a refused" >&2
    echo "[verify-poc-14] NTLMv1 attempt is not evidence that NTLMv1 was disabled" >&2
    exit 2
fi

if echo "$V2" | grep -qiE 'NT_STATUS_HOST_UNREACHABLE|Connection refused|Network is unreachable|Name or service not known'; then
    echo "[verify-poc-14] HARNESS ERROR: cannot reach $DC over SMB" >&2
    exit 2
fi

# --- NTLMv1 refused: the downgrade is closed ---
if echo "$V1" | grep -qiE 'NT_STATUS_LOGON_FAILURE|NT_STATUS_ACCESS_DENIED|NT_STATUS_INVALID_LOGON_HOURS|NT_STATUS_NOT_SUPPORTED'; then
    echo "[verify-poc-14] DC refused the NTLMv1 session setup while NTLMv2 succeeded"
    echo "[verify-poc-14] LmCompatibilityLevel enforces NTLMv2 -- PoC BLOCKED"
    exit 0
fi

# --- NTLMv1 accepted: still downgradable ---
if [ "$V1_RC" -eq 0 ]; then
    echo "[verify-poc-14] DC ACCEPTED an NTLMv1 session setup -- downgrade still allowed" >&2
    echo "[verify-poc-14] captured NTLMv1 responses are crackable offline regardless of password" >&2
    exit 1
fi

echo "[verify-poc-14] no recognised NTLM result (v1 rc=$V1_RC) - INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-14] unrecognised output is not evidence of remediation" >&2
exit 1
