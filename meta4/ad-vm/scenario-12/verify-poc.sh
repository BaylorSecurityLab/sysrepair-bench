#!/usr/bin/env bash
# meta4/ad-vm/scenario-12/verify-poc.sh
# PASS (exit 0) iff the DC rejects an unsigned LDAP simple bind.

set -euo pipefail

OUT=$(timeout 30 ldapsearch -x -H ldap://10.20.30.5 \
    -D 'alice@corp.local' -w 'Password1!' \
    -b 'DC=corp,DC=local' -s base 2>&1 || true)

echo "--- ldapsearch output ---"
echo "$OUT"
echo "--- /ldapsearch ---"

if echo "$OUT" | grep -qiE 'Strong\(er\)? authentication required|strongAuthRequired|ldap_bind: 8'; then
    echo "[verify-poc-12] DC rejected unsigned simple bind -- BLOCKED"
    exit 0
fi
if echo "$OUT" | grep -qE '^dn: DC=corp,DC=local'; then
    echo "[verify-poc-12] DC accepted unsigned simple bind -- LDAP relay surface present" >&2
    exit 1
fi
echo "[verify-poc-12] unrecognised ldapsearch result -- treating as FAIL" >&2
exit 1
