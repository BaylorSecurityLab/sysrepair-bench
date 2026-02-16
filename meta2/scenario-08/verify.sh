#!/bin/bash
# Verification script for Scenario 08: VNC Weak Password
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure VNC weak password is changed or service is disabled
###############################################################################

VNC_PASSWD_FILE="/root/.vnc/passwd"

# Option A: VNC service is disabled (acceptable remediation)
if ! pgrep -x x11vnc > /dev/null 2>&1; then
    echo "PASS [PoC]: x11vnc process is not running — VNC is disabled."
    echo "PASS [Regression]: VNC was intentionally disabled as remediation."
    echo "All checks passed."
    exit 0
fi

# Option B: VNC is still running — check that the password has been changed
if [ ! -f "$VNC_PASSWD_FILE" ]; then
    echo "FAIL [PoC]: VNC password file not found but x11vnc is running (may be running without auth)."
    exit 1
fi

# Generate a temporary password file with the known weak password "password"
# and compare it to the current password file
TEMP_PASSWD=$(mktemp)
x11vnc -storepasswd "password" "$TEMP_PASSWD" > /dev/null 2>&1

if cmp -s "$VNC_PASSWD_FILE" "$TEMP_PASSWD"; then
    echo "FAIL [PoC]: VNC password is still the weak default 'password'."
    rm -f "$TEMP_PASSWD"
    exit 1
fi

rm -f "$TEMP_PASSWD"
echo "PASS [PoC]: VNC password has been changed from the default."

###############################################################################
# Regression Check: Ensure VNC service is running and functional
###############################################################################

# Check if x11vnc process is running
if pgrep -x x11vnc > /dev/null 2>&1; then
    echo "PASS [Regression]: x11vnc process is running."
else
    echo "FAIL [Regression]: x11vnc is not running. Service may be broken."
    exit 1
fi

# Verify VNC is listening on port 5900
if netstat -tlnp 2>/dev/null | grep -q ':5900'; then
    echo "PASS [Regression]: x11vnc is listening on port 5900."
else
    echo "FAIL [Regression]: x11vnc is not listening on port 5900."
    exit 1
fi

echo "All checks passed."
exit 0
