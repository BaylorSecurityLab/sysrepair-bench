#!/bin/bash
# Scenario 40: /etc/passwd writable by others
#
# PoC checks:        /etc/passwd is not world-writable, has sane mode/ownership,
#                    and an unprivileged user really cannot open it for write
# Regression checks: the accounts still exist and sshd is still up
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "fixed the mode bits but killed sshd" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC Test: /etc/passwd should not be world-writable ---
PERMS=$(stat -c "%a" /etc/passwd 2>/dev/null || true)
OWNER=$(stat -c "%U:%G" /etc/passwd 2>/dev/null || true)

# Check that others can't write (last digit should be 4 or 0)
OTHERS_PERM=${PERMS: -1}
if [[ "$OTHERS_PERM" == "6" ]] || [[ "$OTHERS_PERM" == "2" ]] || [[ "$OTHERS_PERM" == "7" ]] || [[ "$OTHERS_PERM" == "3" ]]; then
    record_poc passwd_not_world_writable 0 "/etc/passwd is world-writable (permissions: ${PERMS:-unknown})"
else
    record_poc passwd_not_world_writable 1
fi

# Check permissions are correct (should be 644)
if [[ "$PERMS" == "644" ]]; then
    record_poc passwd_permissions_correct 1
elif echo "$PERMS" | grep -qE '^6[0-4][0-4]$'; then
    record_poc passwd_permissions_correct 1
else
    record_poc passwd_permissions_correct 0 "/etc/passwd has unexpected permissions (${PERMS:-unknown})"
fi

# Check ownership
if [[ "$OWNER" == "root:root" ]]; then
    record_poc passwd_ownership_correct 1
else
    record_poc passwd_ownership_correct 0 "/etc/passwd has wrong ownership (${OWNER:-unknown})"
fi

# --- PoC Behavioral Test: a non-root user cannot write to /etc/passwd at runtime ---
# This exercises the live kernel permission check, not just the stat bits.
# Baseline: /etc/passwd is 0666 -> sysadmin can write -> probe PASSES at kernel level -> [PoC] FAILS.
# Remediated: /etc/passwd is 0644 -> sysadmin cannot write -> [PoC] PASSES.
if id sysadmin >/dev/null 2>&1; then
    if su -s /bin/sh -c 'test -w /etc/passwd' sysadmin 2>/dev/null; then
        record_poc sysadmin_cannot_write_passwd 0 "live write-probe shows sysadmin CAN write /etc/passwd"
    else
        record_poc sysadmin_cannot_write_passwd 1
    fi

    # Belt-and-braces: exercise the real open(2) permission check as sysadmin.
    # WAS DESTRUCTIVE: this used to `echo "# probe" >> /etc/passwd`, actually
    # MUTATING GROUND TRUTH on the vulnerable baseline, and only best-effort
    # `sed -i`'d it back. A verifier must never leave the system altered.
    # Opening the file for append with `exec 3>>` runs the identical kernel
    # permission check but writes zero bytes, so /etc/passwd is untouched.
    PASSWD_SUM_BEFORE=$(md5sum /etc/passwd 2>/dev/null | awk '{print $1}' || true)
    if su -s /bin/sh -c 'exec 3>>/etc/passwd' sysadmin 2>/dev/null; then
        record_poc sysadmin_write_open_rejected 0 "sysadmin can open /etc/passwd for writing at runtime"
    else
        record_poc sysadmin_write_open_rejected 1
    fi
    PASSWD_SUM_AFTER=$(md5sum /etc/passwd 2>/dev/null | awk '{print $1}' || true)
    if [[ "$PASSWD_SUM_BEFORE" != "$PASSWD_SUM_AFTER" ]]; then
        record_poc write_probe_non_destructive 0 "the write-probe altered /etc/passwd (verifier must be non-destructive)"
    else
        record_poc write_probe_non_destructive 1
    fi
else
    echo "WARN [PoC]: sysadmin user missing, skipping live write-probe"
fi

# --- Regression Test: Users should still exist and auth should work ---
if id sysadmin > /dev/null 2>&1; then
    record_reg sysadmin_user_exists 1
else
    record_reg sysadmin_user_exists 0 "sysadmin user is missing"
fi

if id webadmin > /dev/null 2>&1; then
    record_reg webadmin_user_exists 1
else
    record_reg webadmin_user_exists 0 "webadmin user is missing"
fi

# The image CMD boots sshd (see .preserve-cmd) and this verifier deliberately
# does NOT start it: the remote-access service must survive the re-permissioning
# of /etc/passwd. A dead sshd is a FAILURE, not something verify.sh repairs.
if pgrep -x sshd > /dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running"
fi

verify_finish
