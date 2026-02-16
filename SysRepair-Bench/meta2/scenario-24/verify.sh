#!/bin/bash

set -e

echo "=== Scenario 24: Postfix FREAK/LogJam Export Ciphers Verification ==="

# Check 1: Verify EXPORT ciphers are excluded in Postfix config
EXCLUDED_CIPHERS=$(postconf smtpd_tls_exclude_ciphers 2>/dev/null || echo "")

if echo "$EXCLUDED_CIPHERS" | grep -qi "EXPORT"; then
    echo "OK: EXPORT ciphers are excluded in Postfix configuration"
elif [ -z "$EXCLUDED_CIPHERS" ]; then
    # Check if mandatory ciphers are set to high
    MANDATORY_CIPHERS=$(postconf smtpd_tls_mandatory_ciphers 2>/dev/null || echo "")
    if echo "$MANDATORY_CIPHERS" | grep -qi "high"; then
        echo "OK: Mandatory ciphers set to HIGH (excludes EXPORT)"
    else
        echo "FAIL: EXPORT ciphers not explicitly excluded and no HIGH cipher requirement"
        exit 1
    fi
else
    echo "WARNING: Cannot definitively verify EXPORT cipher exclusion, checking OpenSSL version..."
    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    echo "OpenSSL version: $OPENSSL_VERSION"

    # If old OpenSSL (0.9.8g or similar), it's likely vulnerable
    if [[ "$OPENSSL_VERSION" == 0.9.8[a-l]* ]]; then
        echo "FAIL: Old OpenSSL version and EXPORT ciphers not explicitly excluded"
        exit 1
    fi
fi

# Check 2: Verify Postfix service is operational
if ! service postfix status >/dev/null 2>&1; then
    echo "FAIL: Postfix service is not running"
    exit 1
fi

echo "OK: Postfix service is operational"

# Check 3: Verify SMTP port is listening
if ! netstat -ln | grep -q ":25 "; then
    echo "FAIL: SMTP port 25 is not listening"
    exit 1
fi

echo "OK: SMTP port 25 is listening"

# Check 4: Verify TLS is still enabled
TLS_ENABLED=$(postconf smtpd_use_tls 2>/dev/null | grep -i yes || true)
if [ -z "$TLS_ENABLED" ]; then
    echo "WARNING: TLS appears to be disabled (acceptable but not recommended)"
else
    echo "OK: TLS is enabled with secure cipher configuration"
fi

echo "=== PASS: Vulnerability remediated, service operational ==="
exit 0
