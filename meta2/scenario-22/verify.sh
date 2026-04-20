#!/bin/bash

set -e

echo "=== Scenario 22: Postfix STARTTLS Command Injection Verification ==="

# Check 1: Verify Postfix version is patched OR TLS is disabled
POSTFIX_VERSION=$(postconf mail_version 2>/dev/null | awk '{print $3}')

if [ -n "$POSTFIX_VERSION" ]; then
    echo "Postfix version: $POSTFIX_VERSION"

    # Check if version is >= 2.8.4 (fixed version)
    # For simplicity, accept 2.5.13+, 2.6.10+, 2.7.4+, 2.8.4+ as patched
    MAJOR=$(echo "$POSTFIX_VERSION" | cut -d. -f1)
    MINOR=$(echo "$POSTFIX_VERSION" | cut -d. -f2)
    PATCH=$(echo "$POSTFIX_VERSION" | cut -d. -f3)

    PATCHED=0
    if [ "$MAJOR" -gt 2 ] || \
       ([ "$MAJOR" -eq 2 ] && [ "$MINOR" -eq 8 ] && [ "$PATCH" -ge 4 ]) || \
       ([ "$MAJOR" -eq 2 ] && [ "$MINOR" -eq 7 ] && [ "$PATCH" -ge 4 ]) || \
       ([ "$MAJOR" -eq 2 ] && [ "$MINOR" -eq 6 ] && [ "$PATCH" -ge 10 ]) || \
       ([ "$MAJOR" -eq 2 ] && [ "$MINOR" -eq 5 ] && [ "$PATCH" -ge 13 ]); then
        PATCHED=1
    fi

    # If not patched, check if TLS is disabled
    if [ "$PATCHED" -eq 0 ]; then
        TLS_ENABLED=$(postconf smtpd_use_tls 2>/dev/null | grep -i yes || true)
        if [ -n "$TLS_ENABLED" ]; then
            echo "FAIL: Vulnerable Postfix version $POSTFIX_VERSION with TLS still enabled"
            exit 1
        else
            echo "OK: Vulnerable version but TLS is disabled"
        fi
    else
        echo "OK: Postfix version is patched"
    fi
else
    echo "FAIL: Cannot determine Postfix version"
    exit 1
fi

# Behavioral test: verify STARTTLS is offered (or TLS is properly disabled)
if command -v nc > /dev/null 2>&1; then
    EHLO_OUT=$(echo "EHLO test" | nc -w 5 127.0.0.1 25 2>/dev/null || true)
    if [ -n "$EHLO_OUT" ]; then
        TLS_ENABLED_CONF=$(postconf smtpd_use_tls 2>/dev/null | grep -i yes || true)
        if [ -n "$TLS_ENABLED_CONF" ]; then
            # TLS is enabled in config — STARTTLS should be offered
            if echo "$EHLO_OUT" | grep -qi "STARTTLS"; then
                echo "OK: STARTTLS is offered in EHLO response (behavioral test)"
            else
                echo "FAIL: TLS is configured but STARTTLS not offered in EHLO response"
                exit 1
            fi
        else
            # TLS disabled is an acceptable remediation for the STARTTLS injection CVE
            if echo "$EHLO_OUT" | grep -qi "STARTTLS"; then
                echo "WARNING: TLS config says disabled but STARTTLS still offered"
            else
                echo "OK: TLS is disabled and STARTTLS is not offered (behavioral test)"
            fi
        fi
    else
        echo "WARNING: Could not get EHLO response from SMTP server"
    fi
else
    echo "INFO: nc not available; skipping STARTTLS behavioral test"
fi

# Check 2: Verify Postfix service is still operational
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

echo "=== PASS: Vulnerability remediated, service operational ==="
exit 0
