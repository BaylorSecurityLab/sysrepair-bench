#!/bin/bash
# Verification script for Scenario 25: Cleartext Transmission of Sensitive Information via HTTP
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure HTTPS is configured and login pages redirect from HTTP
###############################################################################

# Check that the ssl module is enabled
if ! apache2ctl -M 2>/dev/null | grep -qi 'ssl_module'; then
    echo "FAIL [PoC]: Apache ssl_module is not enabled — HTTPS not available."
    exit 1
fi

# Check that an SSL certificate file exists and is referenced in config
SSL_CERT=$(grep -r 'SSLCertificateFile' /etc/apache2/ 2>/dev/null | grep -v '#' | head -1)
if [ -z "$SSL_CERT" ]; then
    echo "FAIL [PoC]: No SSLCertificateFile directive found in Apache config."
    exit 1
fi

# Extract the cert path and verify the file exists
CERT_PATH=$(echo "$SSL_CERT" | sed 's/.*SSLCertificateFile[[:space:]]*//' | tr -d ' ')
if [ ! -f "$CERT_PATH" ]; then
    echo "FAIL [PoC]: SSL certificate file '$CERT_PATH' does not exist."
    exit 1
fi

# Check that SSLEngine is on somewhere in the config
if ! grep -r 'SSLEngine[[:space:]]*on' /etc/apache2/ 2>/dev/null | grep -qv '#'; then
    echo "FAIL [PoC]: SSLEngine is not enabled in any Apache config."
    exit 1
fi

# Check for HTTP-to-HTTPS redirect for login or phpmyadmin paths
REDIRECT_FOUND=0
if grep -r -E '(RewriteRule|Redirect).*login.*https' /etc/apache2/ 2>/dev/null | grep -qv '#'; then
    REDIRECT_FOUND=1
fi
if grep -r -E '(RewriteRule|Redirect).*phpmyadmin.*https' /etc/apache2/ 2>/dev/null | grep -qv '#'; then
    REDIRECT_FOUND=1
fi
# Also accept a blanket redirect of all HTTP to HTTPS
if grep -r -E '(RewriteRule|Redirect).*https.*\[R=' /etc/apache2/ 2>/dev/null | grep -qv '#'; then
    REDIRECT_FOUND=1
fi
if grep -r -E 'Redirect permanent.*/.*https://' /etc/apache2/ 2>/dev/null | grep -qv '#'; then
    REDIRECT_FOUND=1
fi

if [ "$REDIRECT_FOUND" -eq 0 ]; then
    echo "FAIL [PoC]: No HTTP-to-HTTPS redirect found for login/phpmyadmin pages."
    exit 1
fi

echo "PASS [PoC]: HTTPS is configured with SSL cert and HTTP redirect for sensitive pages (config check)."

# Behavioral test: verify HTTPS works and HTTP login redirects to HTTPS
# Start Apache if not running
if ! pgrep -x apache2 > /dev/null 2>&1; then
    apache2ctl start > /dev/null 2>&1
    sleep 2
fi

if command -v curl > /dev/null 2>&1; then
    # Test 1: HTTPS should serve content
    HTTPS_OUT=$(curl -k -s -o /dev/null -w "%{http_code}" https://127.0.0.1/ 2>/dev/null || true)
    if [ "$HTTPS_OUT" = "200" ] || [ "$HTTPS_OUT" = "301" ] || [ "$HTTPS_OUT" = "302" ]; then
        echo "PASS [PoC]: HTTPS is serving content (HTTP $HTTPS_OUT, behavioral test)."
    elif [ -n "$HTTPS_OUT" ] && [ "$HTTPS_OUT" != "000" ]; then
        echo "PASS [PoC]: HTTPS responded with HTTP $HTTPS_OUT (behavioral test)."
    else
        echo "FAIL [PoC]: HTTPS on port 443 is not responding."
        exit 1
    fi

    # Test 2: HTTP login should redirect to HTTPS
    LOGIN_OUT=$(curl -s -o /dev/null -w "%{http_code}:%{redirect_url}" http://127.0.0.1/login/ 2>/dev/null || true)
    HTTP_CODE=$(echo "$LOGIN_OUT" | cut -d: -f1)
    REDIR_URL=$(echo "$LOGIN_OUT" | cut -d: -f2-)

    if [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
        if echo "$REDIR_URL" | grep -qi "https://"; then
            echo "PASS [PoC]: HTTP login redirects to HTTPS (behavioral test)."
        else
            echo "WARN [PoC]: HTTP login redirects but not to HTTPS: $REDIR_URL"
        fi
    elif [ "$HTTP_CODE" = "200" ]; then
        # Served over plain HTTP without redirect — check if it is the login page
        LOGIN_BODY=$(curl -s http://127.0.0.1/login/ 2>/dev/null || true)
        if echo "$LOGIN_BODY" | grep -qi "password\|login"; then
            echo "FAIL [PoC]: Login page served over plain HTTP without redirect to HTTPS."
            exit 1
        fi
    fi
elif command -v wget > /dev/null 2>&1; then
    WGET_OUT=$(wget --no-check-certificate -q -O /dev/null https://127.0.0.1/ 2>&1 || true)
    if echo "$WGET_OUT" | grep -qi "error\|failed"; then
        echo "FAIL [PoC]: HTTPS not accessible via wget."
        exit 1
    else
        echo "PASS [PoC]: HTTPS accessible via wget (behavioral test)."
    fi
else
    echo "INFO [PoC]: Neither curl nor wget available; skipping HTTPS behavioral test."
fi

###############################################################################
# Regression Check: Ensure Apache is running and serving pages
###############################################################################

# Start Apache if not running
if ! pgrep -x apache2 > /dev/null 2>&1; then
    apache2ctl start > /dev/null 2>&1
    sleep 2
fi

# Check if Apache process is running
if ! pgrep -x apache2 > /dev/null 2>&1; then
    echo "FAIL [Regression]: Apache is not running."
    exit 1
fi

echo "PASS [Regression]: Apache is running."

# Check Apache is listening on port 80 or 443
if netstat -tlnp 2>/dev/null | grep -qE ':(80|443)\b'; then
    echo "PASS [Regression]: Apache is listening on HTTP/HTTPS port."
else
    echo "FAIL [Regression]: Apache is not listening on port 80 or 443."
    exit 1
fi

echo "All checks passed."
exit 0
