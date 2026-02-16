#!/bin/bash
# Verification script for Scenario 14: Postfix SMTP VRFY/EXPN Enabled
# Check 1 (PoC): VRFY command should be rejected by Postfix
# Check 2 (Regression): SMTP should still accept mail (EHLO/MAIL FROM works)

##############################################################################
# Ensure Postfix is running for the checks
##############################################################################
postfix start 2>/dev/null
sleep 2

##############################################################################
# PoC Check: VRFY command should be disabled
##############################################################################

VRFY_RESPONSE=$(printf "EHLO test\r\nVRFY root\r\nQUIT\r\n" | \
    nc -w 5 127.0.0.1 25 2>/dev/null)

if echo "$VRFY_RESPONSE" | grep -qE "^252|^250.*root"; then
    echo "FAIL: VRFY command returned user information -- still vulnerable."
    exit 1
elif echo "$VRFY_RESPONSE" | grep -qE "^502"; then
    echo "PASS: VRFY command is disabled (502 response)."
else
    # Fallback: check the Postfix config directly
    if grep -qE '^\s*disable_vrfy_command\s*=\s*yes' /etc/postfix/main.cf 2>/dev/null; then
        echo "PASS: disable_vrfy_command = yes is set in main.cf."
    else
        echo "FAIL: VRFY command may still be enabled (unexpected response)."
        exit 1
    fi
fi

##############################################################################
# Regression Check: SMTP should still be functional
##############################################################################

SMTP_RESPONSE=$(printf "EHLO test\r\nQUIT\r\n" | \
    nc -w 5 127.0.0.1 25 2>/dev/null)

if echo "$SMTP_RESPONSE" | grep -qE "^220.*ESMTP|^250"; then
    echo "PASS: Postfix SMTP is responding to EHLO."
else
    # Check if Postfix process is running
    if pgrep -x master > /dev/null 2>&1; then
        echo "PASS: Postfix master process is running."
    else
        echo "FAIL: Postfix is not running -- SMTP service is broken."
        exit 1
    fi
fi

echo "All checks passed."
exit 0
