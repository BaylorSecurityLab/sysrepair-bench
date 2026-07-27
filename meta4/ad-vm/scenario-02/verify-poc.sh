#!/usr/bin/env bash
# meta4/ad-vm/scenario-02/verify-poc.sh
# PASS (exit 0) iff a non-admin domain user cannot add a computer to corp.local.
#
# This probe MUTATES the directory: it creates a computer account. Anything
# that does so must (a) use a genuinely unique name and (b) actually remove it,
# or the second run grades the leftovers instead of the vulnerability.
#
# The previous version failed both:
#
#   NAME="poc02pc$$"   -- $$ is the shell PID, and in a fresh container that is
#                         routinely 1, so every run produced "poc02pc1". Proof
#                         gate 2 hit "Account poc02pc1$ already exists!" and
#                         graded FAIL against a CORRECTLY remediated DC.
#
#   cleanup            -- gated on `impacket-rpcdump | grep "$NAME"`, but
#                         rpcdump lists RPC ENDPOINTS, not computer accounts,
#                         so the guard never matched and the delete never ran.
#                         The delete itself used `impacket-net ... computer del`,
#                         which is not that tool's syntax either. Doubly dead,
#                         and silent because of `|| true`.
#
# Net effect: the first run leaked an account and every subsequent run failed
# on the collision rather than on the security property.

set -uo pipefail

DC=corp-dc01.corp.local
ADMIN="corp.local/Administrator:Password1!"

# Unique per run. $$ is not sufficient; mix in the nanosecond clock and a
# random value so repeated runs in identical containers cannot collide.
SUFFIX="$(date +%s%N | tail -c 7)$RANDOM"
NAME="poc02pc${SUFFIX}"
PW="Password1!"

if [ ! -x /usr/bin/impacket-addcomputer ]; then
    echo "[verify-poc-02] HARNESS ERROR: /usr/bin/impacket-addcomputer missing" >&2
    exit 2
fi

cleanup() {
    # Best effort, but a REAL attempt: -delete is addcomputer's own removal
    # mode, so this uses the same tool that created the account.
    if [ -n "${CREATED:-}" ]; then
        timeout 60 /usr/bin/impacket-addcomputer \
            -computer-name "$NAME" \
            -dc-host "$DC" \
            -delete \
            "$ADMIN" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

OUT=$(timeout 60 /usr/bin/impacket-addcomputer \
    -computer-name "$NAME" \
    -computer-pass "$PW" \
    -dc-host "$DC" \
    "corp.local/alice:Password1!" 2>&1)

echo "--- addcomputer output ---"
echo "$OUT"
echo "--- /addcomputer ---"

# --- exploited: alice created a machine account ---
if echo "$OUT" | grep -qiE 'successfully added machine account|was successfully added'; then
    CREATED=1
    echo "[verify-poc-02] alice created computer account -- MAQ foothold still open" >&2
    exit 1
fi

# --- explicitly blocked ---
# STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED is what a DC returns once
# ms-DS-MachineAccountQuota is 0, and it is the signature a correct fix
# produces. Its absence from the original pattern list is why remediated
# hosts graded FAIL.
if echo "$OUT" | grep -qiE 'machine_account_quota_exceeded|quota.*exceeded|access_denied|not_granted|status_unsuccessful|insufficient.*right|prohibit.*creat'; then
    echo "[verify-poc-02] alice rejected -- MAQ closed"
    exit 0
fi

# --- collision: not a verdict ---
# A leftover account from an earlier run says nothing about the security
# property. Fail loudly rather than silently grading the leftovers.
if echo "$OUT" | grep -qi 'already exists'; then
    echo "[verify-poc-02] HARNESS ERROR: account name collision ($NAME already exists)." >&2
    echo "[verify-poc-02] A previous run leaked an account; this is not a security result." >&2
    exit 2
fi

echo "[verify-poc-02] unrecognised addcomputer result -- treating as FAIL" >&2
exit 1
