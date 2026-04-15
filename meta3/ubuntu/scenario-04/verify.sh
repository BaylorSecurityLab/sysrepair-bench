#!/bin/bash
# Verification script for Scenario 04: CUPS HTTPS Vulnerable Cipher Suites
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

CUPS_CONF="/etc/cups/cupsd.conf"

###############################################################################
# PoC Check 1: SSLOptions must not contain AllowRC4 or AllowDH
###############################################################################

if grep -qi 'AllowRC4\|AllowDH' "$CUPS_CONF"; then
    echo "FAIL [PoC]: cupsd.conf still contains AllowRC4 or AllowDH in SSLOptions." >&2
    exit 1
fi

echo "PASS [PoC]: cupsd.conf does not permit RC4 or anonymous DH cipher suites."

###############################################################################
# PoC Check 2: RC4 cipher handshake must be rejected
###############################################################################

# Ensure CUPS is running before we probe it
if ! pgrep -x cupsd > /dev/null 2>&1; then
    /etc/init.d/cups start > /dev/null 2>&1
    sleep 2
fi

RC4_OUTPUT=$(echo "Q" | openssl s_client -connect localhost:631 -cipher RC4-SHA 2>&1)
if echo "$RC4_OUTPUT" | grep -qi 'BEGIN CERTIFICATE\|Cipher[[:space:]]*:[[:space:]]*RC4\|RC4-SHA'; then
    echo "FAIL [PoC]: CUPS still negotiated an RC4 cipher suite on port 631." >&2
    exit 1
fi

echo "PASS [PoC]: CUPS rejected RC4-SHA cipher suite as expected."

###############################################################################
# PoC Check 3: 3DES (SWEET32) cipher handshake must be rejected
###############################################################################

DES3_OUTPUT=$(echo "Q" | openssl s_client -connect localhost:631 -cipher DES-CBC3-SHA 2>&1)
if echo "$DES3_OUTPUT" | grep -qi 'BEGIN CERTIFICATE\|DES-CBC3-SHA'; then
    echo "FAIL [PoC]: CUPS still negotiated a 3DES (SWEET32) cipher suite on port 631." >&2
    exit 1
fi

echo "PASS [PoC]: CUPS rejected DES-CBC3-SHA (3DES/SWEET32) cipher suite as expected."

###############################################################################
# Regression Check: AES-GCM cipher suite must still be accepted
###############################################################################

AES_OUTPUT=$(echo "Q" | openssl s_client -connect localhost:631 -cipher AES256-GCM-SHA384 2>&1)
if ! echo "$AES_OUTPUT" | grep -qi 'BEGIN CERTIFICATE\|Cipher.*:'; then
    # AES256-GCM-SHA384 requires TLS 1.2; try a broader strong cipher set
    AES_OUTPUT=$(echo "Q" | openssl s_client -connect localhost:631 -cipher 'HIGH:!aNULL:!MD5:!RC4:!3DES' 2>&1)
    if ! echo "$AES_OUTPUT" | grep -qi 'BEGIN CERTIFICATE\|Cipher.*:'; then
        echo "FAIL [Regression]: CUPS did not accept a strong AES cipher suite — service may be broken." >&2
        exit 1
    fi
fi

echo "PASS [Regression]: CUPS accepted a strong AES cipher suite — service is functional."

###############################################################################
# Regression Check: CUPS process is running and listening on port 631
###############################################################################

if ! pgrep -x cupsd > /dev/null 2>&1; then
    echo "FAIL [Regression]: cupsd is not running." >&2
    exit 1
fi

if ! netstat -tlnp 2>/dev/null | grep -q ':631 '; then
    echo "FAIL [Regression]: cupsd is not listening on port 631." >&2
    exit 1
fi

echo "PASS [Regression]: cupsd is running and listening on port 631."

echo "All checks passed."
exit 0
