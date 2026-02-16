#!/bin/bash
# Scenario 16: vsftpd no SSL/TLS enforcement
# Verification: PoC should fail (SSL enabled) AND functionality test should pass

PASS=true

# --- PoC Test: SSL should be enabled ---
SSL_ENABLE=$(grep -E '^\s*ssl_enable' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$SSL_ENABLE" != "YES" ]]; then
    echo "FAIL [PoC]: ssl_enable is not YES ($SSL_ENABLE)"
    PASS=false
else
    echo "PASS [PoC]: ssl_enable is YES"
fi

# Check that SSL is forced for local logins
FORCE_SSL=$(grep -E '^\s*force_local_logins_ssl' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$FORCE_SSL" != "YES" ]]; then
    echo "FAIL [PoC]: force_local_logins_ssl is not YES"
    PASS=false
else
    echo "PASS [PoC]: force_local_logins_ssl is YES"
fi

# Check SSL certificate exists
CERT_FILE=$(grep -E '^\s*rsa_cert_file' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [ -n "$CERT_FILE" ] && [ -f "$CERT_FILE" ]; then
    echo "PASS [PoC]: SSL certificate exists at $CERT_FILE"
else
    echo "FAIL [PoC]: SSL certificate not configured or missing"
    PASS=false
fi

# --- Regression Test: vsftpd should be running ---
if pgrep -x vsftpd > /dev/null 2>&1; then
    echo "PASS [Regression]: vsftpd process is running"
else
    /usr/sbin/vsftpd /etc/vsftpd.conf &
    sleep 1
    if pgrep -x vsftpd > /dev/null 2>&1; then
        echo "PASS [Regression]: vsftpd started successfully"
    else
        echo "FAIL [Regression]: vsftpd is not running and cannot be started"
        PASS=false
    fi
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
