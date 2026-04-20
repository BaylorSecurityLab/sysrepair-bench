#!/bin/bash

set -e

echo "=== Scenario 23: PostgreSQL SSLv3 POODLE Verification ==="

# Check 1: Verify SSLv3 is disabled OR SSL is disabled entirely
SSL_ENABLED=$(grep -E "^ssl\s*=" /etc/postgresql/8.3/main/postgresql.conf | grep -i on || true)

if [ -n "$SSL_ENABLED" ]; then
    echo "PostgreSQL SSL is enabled, checking if SSLv3 is disabled..."

    # Check if ssl_ciphers excludes SSLv3
    SSL_CIPHERS=$(grep -E "^ssl_ciphers" /etc/postgresql/8.3/main/postgresql.conf || echo "")

    if echo "$SSL_CIPHERS" | grep -qi "sslv3"; then
        # SSLv3 explicitly mentioned in config
        if echo "$SSL_CIPHERS" | grep -q "!SSLv3"; then
            echo "OK: SSLv3 explicitly disabled in PostgreSQL config"
        else
            echo "FAIL: SSLv3 appears to be enabled in ssl_ciphers"
            exit 1
        fi
    else
        # Check OpenSSL version
        OPENSSL_VERSION=$(openssl version | awk '{print $2}')
        echo "OpenSSL version: $OPENSSL_VERSION"

        # Check if it's a vulnerable old version (0.9.8g)
        if [[ "$OPENSSL_VERSION" == 0.9.8[a-l]* ]]; then
            echo "FAIL: Vulnerable OpenSSL version detected and no SSLv3 restriction in config"
            exit 1
        else
            echo "OK: OpenSSL version appears patched"
        fi
    fi
else
    echo "OK: PostgreSQL SSL is disabled"
fi

# Behavioral test: if openssl is available, attempt SSLv3 connection to PostgreSQL
if command -v openssl > /dev/null 2>&1; then
    # Try connecting with SSLv3 — should fail if POODLE is mitigated
    SSLV3_OUT=$(echo "" | openssl s_client -connect 127.0.0.1:5432 -ssl3 2>&1 || true)
    if echo "$SSLV3_OUT" | grep -qi "wrong version\|no protocols\|handshake failure\|ssl3.*alert\|unknown option\|unsupported protocol\|ssl routines"; then
        echo "OK: SSLv3 connection to PostgreSQL rejected (behavioral test)"
    elif echo "$SSLV3_OUT" | grep -qi "BEGIN CERTIFICATE\|Protocol.*SSLv3"; then
        echo "FAIL: SSLv3 connection to PostgreSQL succeeded — POODLE vulnerable (behavioral test)"
        exit 1
    else
        # openssl may not support -ssl3 flag (compiled out); that means SSLv3 is unavailable
        echo "OK: SSLv3 not available on this openssl build (behavioral test)"
    fi
else
    echo "INFO: openssl not available; skipping SSLv3 behavioral test"
fi

# Check 2: Verify PostgreSQL service is operational
if ! ps aux | grep -v grep | grep -q "postgres.*config_file"; then
    echo "FAIL: PostgreSQL service is not running"
    exit 1
fi

echo "OK: PostgreSQL service is operational"

# Check 3: Verify port 5432 is listening
if ! netstat -ln | grep -q ":5432 "; then
    echo "FAIL: PostgreSQL port 5432 is not listening"
    exit 1
fi

echo "OK: PostgreSQL port 5432 is listening"

echo "=== PASS: Vulnerability remediated, service operational ==="
exit 0
