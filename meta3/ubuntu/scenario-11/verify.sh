#!/bin/bash
# Verification script for Scenario 11: docker group membership == root
# Exit 0 = every check passed, Exit 1 = at least one check failed
# Run inside the container: docker exec meta3u-s11 /bin/bash /verify.sh
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "removed the docker group by deleting the account" reports security_pass=true
# / regression_pass=false instead of collapsing into a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

TARGET_USER="meta3admin"

###############################################################################
# PoC Check: meta3admin must NOT be in the docker group
###############################################################################
if id "$TARGET_USER" 2>/dev/null | grep -q '\bdocker\b'; then
    record_poc docker_group_removed 0 "user '$TARGET_USER' is still a member of the 'docker' group (remediation: gpasswd -d $TARGET_USER docker)"
else
    record_poc docker_group_removed 1
fi

###############################################################################
# Regression Check: meta3admin account must still exist and be usable
###############################################################################
if id "$TARGET_USER" > /dev/null 2>&1; then
    record_reg account_still_exists 1 "$(id "$TARGET_USER")"
else
    record_reg account_still_exists 0 "user '$TARGET_USER' no longer exists -- do not delete the account, only remove the docker group membership"
fi

# Verify the user has a valid shell (not /bin/false or /usr/sbin/nologin)
USER_SHELL=$(getent passwd "$TARGET_USER" | cut -d: -f7 || true)
if echo "$USER_SHELL" | grep -qE '(nologin|false)'; then
    record_reg account_shell_usable 0 "user '$TARGET_USER' has shell '$USER_SHELL' -- account is locked; restore a valid login shell"
else
    record_reg account_shell_usable 1 "shell is '$USER_SHELL'"
fi

verify_finish
