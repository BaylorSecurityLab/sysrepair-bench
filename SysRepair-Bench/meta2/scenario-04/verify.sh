#!/bin/bash
# Verification script for Scenario 04: FTP Anonymous Login
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure anonymous FTP login is disabled
###############################################################################

VSFTPD_CONF="/etc/vsftpd.conf"

# Check vsftpd.conf for anonymous_enable setting
ANON_SETTING=$(grep -i '^anonymous_enable' "$VSFTPD_CONF" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')

if [ -z "$ANON_SETTING" ]; then
    echo "FAIL [PoC]: No 'anonymous_enable' directive found — vsftpd may default to allowing anonymous."
    exit 1
fi

if echo "$ANON_SETTING" | grep -qi "YES"; then
    echo "FAIL [PoC]: anonymous_enable is still set to YES in vsftpd.conf."
    exit 1
fi

echo "PASS [PoC]: anonymous_enable is set to NO."

###############################################################################
# Regression Check: Ensure vsftpd is running and functional
###############################################################################

# Check if vsftpd process is running
if pgrep -x vsftpd > /dev/null 2>&1; then
    echo "PASS [Regression]: vsftpd process is running."
else
    # Try to start vsftpd and check again
    /etc/init.d/vsftpd start > /dev/null 2>&1
    sleep 1
    if pgrep -x vsftpd > /dev/null 2>&1; then
        echo "PASS [Regression]: vsftpd process started and is running."
    else
        echo "FAIL [Regression]: vsftpd is not running. Service may be broken."
        exit 1
    fi
fi

# Verify vsftpd is listening on port 21
if netstat -tlnp 2>/dev/null | grep -q ':21'; then
    echo "PASS [Regression]: vsftpd is listening on port 21."
else
    echo "FAIL [Regression]: vsftpd is not listening on port 21."
    exit 1
fi

echo "All checks passed."
exit 0
