#!/bin/bash
# Verification script for Scenario 03: CUPS Deprecated TLS Versions
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

CUPS_CONF="/etc/cups/cupsd.conf"

###############################################################################
# PoC Check 1: SSLOptions must not contain AllowSSL3, AllowTLS1, or AllowTLS11
###############################################################################

if grep -qi 'AllowSSL3\|AllowTLS1[^2]' "$CUPS_CONF"; then
    echo "FAIL [PoC]: cupsd.conf still contains AllowSSL3 or AllowTLS1/AllowTLS11 in SSLOptions." >&2
    exit 1
fi

echo "PASS [PoC]: cupsd.conf does not permit deprecated TLS versions via SSLOptions."

###############################################################################
# PoC Check 2: openssl s_client with -tls1 must be rejected
###############################################################################

# Ensure CUPS is running before we probe it
if ! pgrep -x cupsd > /dev/null 2>&1; then
    /etc/init.d/cups start > /dev/null 2>&1
    sleep 2
fi

TLS1_OUTPUT=$(echo "Q" | openssl s_client -connect localhost:631 -tls1 2>&1)
if echo "$TLS1_OUTPUT" | grep -qi 'BEGIN CERTIFICATE\|Cipher.*:'; then
    echo "FAIL [PoC]: CUPS still accepted a TLSv1.0 connection on port 631." >&2
    exit 1
fi

echo "PASS [PoC]: CUPS rejected TLSv1.0 connection as expected."

###############################################################################
# PoC Check 3: openssl s_client with -tls1_1 must be rejected
###############################################################################

TLS11_OUTPUT=$(echo "Q" | openssl s_client -connect localhost:631 -tls1_1 2>&1)
if echo "$TLS11_OUTPUT" | grep -qi 'BEGIN CERTIFICATE\|Cipher.*:'; then
    echo "FAIL [PoC]: CUPS still accepted a TLSv1.1 connection on port 631." >&2
    exit 1
fi

echo "PASS [PoC]: CUPS rejected TLSv1.1 connection as expected."

###############################################################################
# Regression Check: TLSv1.2 must still be accepted (service functional)
###############################################################################

TLS12_OUTPUT=$(echo "Q" | openssl s_client -connect localhost:631 -tls1_2 2>&1)
if ! echo "$TLS12_OUTPUT" | grep -qi 'BEGIN CERTIFICATE\|Cipher.*:'; then
    echo "FAIL [Regression]: CUPS did not accept a TLSv1.2 connection — service may be broken." >&2
    exit 1
fi

echo "PASS [Regression]: CUPS accepted TLSv1.2 connection — service is functional."

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
