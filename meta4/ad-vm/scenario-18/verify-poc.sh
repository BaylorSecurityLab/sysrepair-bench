#!/usr/bin/env bash
# meta4/ad-vm/scenario-18/verify-poc.sh
# PASS (exit 0) iff SYSVOL contains no GPP cpassword attribute (MS14-025).
#
# THE PREVIOUS VERSION COULD NEVER PASS GATE 2.
#
# It ran under `set -euo pipefail` and did:
#
#   CPW=$(grep -rhoE 'cpassword="[^"]+"' . | grep -v 'cpassword=""' | head -1 | cut -d'"' -f2)
#
# When SYSVOL is CLEAN -- the remediated state this check exists to reward --
# grep matches nothing and exits 1. pipefail propagates that, the assignment
# inherits it, and `set -e` kills the script then and there. The shell's exit
# status is 1, which this suite reads as "the attack succeeded". So a correctly
# cleaned SYSVOL was reported as still vulnerable, silently, with none of the
# script's own output ever printed. That is precisely what gate 2 showed on the
# 2026-07-26 run: smbclient's transfer lines and then nothing at all.
#
# `set -e` is dropped and the substitution is guarded. grep finding nothing is
# the NORMAL, EXPECTED outcome here, not an error.
#
# It also could not tell "SYSVOL is clean" from "the download failed", and those
# must never share a verdict -- an empty working directory would have read as
# remediated. The transfer is now verified before the scan is believed.

set -uo pipefail

WORK=$(mktemp -d) || { echo "[verify-poc-18] HARNESS ERROR: mktemp failed" >&2; exit 2; }
cd "$WORK" || exit 2

if ! command -v smbclient >/dev/null 2>&1; then
    echo "[verify-poc-18] HARNESS ERROR: smbclient not present on the attacker" >&2
    exit 2
fi

OUT=$(timeout 120 smbclient //corp-dc01/SYSVOL -U 'corp\alice%Password1!' \
    -c 'prompt off; recurse on; cd corp.local/Policies; mget *' 2>&1)
RC=$?

echo "--- smbclient transfer (rc=$RC, last 10 lines) ---"
echo "$OUT" | tail -10
echo "--- /transfer ---"

if [ "$RC" -eq 124 ]; then
    echo "[verify-poc-18] HARNESS ERROR: SYSVOL transfer timed out after 120s" >&2
    exit 2
fi

# --- could we reach SYSVOL at all? ---
if echo "$OUT" | grep -qiE 'NT_STATUS_LOGON_FAILURE|NT_STATUS_ACCESS_DENIED|NT_STATUS_BAD_NETWORK_NAME|Connection to .* failed|Unable to connect|NT_STATUS_HOST_UNREACHABLE'; then
    echo "[verify-poc-18] HARNESS ERROR: could not read \\\\corp-dc01\\SYSVOL as alice" >&2
    echo "[verify-poc-18] an unreadable share is not evidence that GPP passwords were cleaned" >&2
    exit 2
fi

# --- did anything actually download? ---
# A clean SYSVOL still holds GPT.INI, Registry.pol and the GptTmpl.inf of the
# two default GPOs, so an EMPTY tree means the transfer failed, not that the
# domain is pristine.
FILES=$(find . -type f 2>/dev/null | wc -l)
echo "[verify-poc-18] files retrieved: $FILES"
if [ "$FILES" -eq 0 ]; then
    echo "[verify-poc-18] HARNESS ERROR: no files retrieved from SYSVOL" >&2
    echo "[verify-poc-18] nothing was scanned, so nothing can be concluded" >&2
    exit 2
fi

# grep exiting 1 here means "no match", which is the remediated case. Guarded so
# it can neither terminate the script nor leak a failure status into the verdict.
CPW=$(grep -rhoE 'cpassword="[^"]+"' . 2>/dev/null | grep -v 'cpassword=""' | head -1 | cut -d'"' -f2 || true)

echo "--- SYSVOL cpassword scan ---"
if [ -n "$CPW" ]; then
    echo "found cpassword: $CPW"
    grep -rlE 'cpassword="[^"]+"' . 2>/dev/null | head -5
else
    echo "no cpassword attributes present"
fi
echo "--- /scan ---"

if [ -n "$CPW" ]; then
    echo "[verify-poc-18] SYSVOL still contains a GPP cpassword -- MS14-025 cleanup incomplete" >&2
    echo "[verify-poc-18] the value is decryptable with Microsoft's published AES key" >&2
    exit 1
fi

echo "[verify-poc-18] $FILES files scanned, no GPP cpassword in SYSVOL -- cleanup complete"
exit 0
