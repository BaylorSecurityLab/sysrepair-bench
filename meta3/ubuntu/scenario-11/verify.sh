#!/bin/bash
# Verification script for Scenario 11: docker group membership == root
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
# Run inside the container: docker exec meta3u-s11 /bin/bash /verify.sh

TARGET_USER="meta3admin"

###############################################################################
# PoC Check: meta3admin must NOT be in the docker group
###############################################################################

if id "$TARGET_USER" 2>/dev/null | grep -q '\bdocker\b'; then
    echo "FAIL [PoC]: User '$TARGET_USER' is still a member of the 'docker' group." >&2
    echo "  Remediation: gpasswd -d $TARGET_USER docker" >&2
    exit 1
fi

echo "PASS [PoC]: User '$TARGET_USER' is not in the 'docker' group."

###############################################################################
# Regression Check: meta3admin account must still exist and be usable
###############################################################################

if ! id "$TARGET_USER" > /dev/null 2>&1; then
    echo "FAIL [Regression]: User '$TARGET_USER' no longer exists. Do not delete the account -- only remove the docker group membership." >&2
    exit 1
fi

echo "PASS [Regression]: User '$TARGET_USER' still exists: $(id $TARGET_USER)"

# Verify the user has a valid shell (not /bin/false or /usr/sbin/nologin)
USER_SHELL=$(getent passwd "$TARGET_USER" | cut -d: -f7)
if echo "$USER_SHELL" | grep -qE '(nologin|false)'; then
    echo "FAIL [Regression]: User '$TARGET_USER' has shell '$USER_SHELL' -- account is locked. Restore a valid login shell." >&2
    exit 1
fi

echo "PASS [Regression]: User '$TARGET_USER' has valid shell '$USER_SHELL'."

echo "All checks passed."
exit 0
