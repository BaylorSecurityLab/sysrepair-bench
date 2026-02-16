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

echo "PASS [PoC]: HTTPS is configured with SSL cert and HTTP redirect for sensitive pages."

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
