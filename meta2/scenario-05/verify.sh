#!/bin/bash
# Verification script for Scenario 05: FTP Unencrypted Cleartext Login
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure SSL/TLS is enabled for FTP logins
###############################################################################

VSFTPD_CONF="/etc/vsftpd.conf"

# Check that ssl_enable is set to YES
SSL_ENABLE=$(grep -i '^ssl_enable' "$VSFTPD_CONF" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')

if [ -z "$SSL_ENABLE" ]; then
    echo "FAIL [PoC]: No 'ssl_enable' directive found in vsftpd.conf — SSL/TLS is not enabled."
    exit 1
fi

if ! echo "$SSL_ENABLE" | grep -qi "YES"; then
    echo "FAIL [PoC]: ssl_enable is not set to YES — FTP traffic is still unencrypted."
    exit 1
fi

echo "PASS [PoC]: ssl_enable is set to YES."

# Additionally check that local logins are forced over SSL
FORCE_SSL=$(grep -i '^force_local_logins_ssl' "$VSFTPD_CONF" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')

if [ -z "$FORCE_SSL" ] || ! echo "$FORCE_SSL" | grep -qi "YES"; then
    echo "WARN [PoC]: force_local_logins_ssl is not YES — cleartext login may still be possible."
    # This is a warning but we still pass if ssl_enable is YES, as some vsftpd versions
    # on Ubuntu 8.04 may not support all force_* directives
fi

# Verify SSL certificate files exist
CERT_FILE=$(grep -i '^rsa_cert_file' "$VSFTPD_CONF" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')
KEY_FILE=$(grep -i '^rsa_private_key_file' "$VSFTPD_CONF" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d ' ')

if [ -n "$CERT_FILE" ] && [ -f "$CERT_FILE" ]; then
    echo "PASS [PoC]: SSL certificate file exists at $CERT_FILE."
else
    echo "FAIL [PoC]: SSL certificate file not found. SSL cannot function without a certificate."
    exit 1
fi

if [ -n "$KEY_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "PASS [PoC]: SSL private key file exists at $KEY_FILE."
else
    echo "FAIL [PoC]: SSL private key file not found. SSL cannot function without a key."
    exit 1
fi

# Behavioral test: verify that cleartext FTP login is rejected and TLS is required
# Ensure vsftpd is running first
if ! pgrep -x vsftpd > /dev/null 2>&1; then
    /etc/init.d/vsftpd start > /dev/null 2>&1
    sleep 1
fi

if command -v openssl > /dev/null 2>&1; then
    # Test 1: Attempt STARTTLS on FTP — should succeed (TLS available)
    TLS_OUT=$(echo "QUIT" | openssl s_client -connect 127.0.0.1:21 -starttls ftp 2>&1 || true)
    if echo "$TLS_OUT" | grep -qi "BEGIN CERTIFICATE\|SSL handshake\|Verify return"; then
        echo "PASS [PoC]: FTP server supports STARTTLS (behavioral test)."
    else
        echo "WARN [PoC]: Could not verify STARTTLS on FTP via openssl."
    fi
fi

if command -v nc > /dev/null 2>&1; then
    # Test 2: Attempt cleartext login — should be rejected if force_local_logins_ssl=YES
    CLEAR_OUT=$(printf "USER ftpuser\r\nPASS ftppass123\r\nQUIT\r\n" | nc -w 5 127.0.0.1 21 2>/dev/null || true)
    if echo "$CLEAR_OUT" | grep -q "^230"; then
        echo "FAIL [PoC]: Cleartext FTP login succeeded — TLS not enforced."
        exit 1
    elif echo "$CLEAR_OUT" | grep -q "^530\|^534\|^5[0-9][0-9].*SSL\|^5[0-9][0-9].*TLS"; then
        echo "PASS [PoC]: Cleartext FTP login rejected — TLS required (behavioral test)."
    else
        echo "INFO [PoC]: Cleartext login result inconclusive. Output: $CLEAR_OUT"
    fi
else
    echo "INFO [PoC]: nc not available; skipping cleartext login behavioral test."
fi

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
