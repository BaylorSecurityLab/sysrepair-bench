#!/bin/bash
# Verification script for Scenario 26: Apache httpOnly Cookie Information Disclosure
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure HttpOnly flag is set on cookies via mod_headers
###############################################################################

# Check that mod_headers is enabled
if ! apache2ctl -M 2>/dev/null | grep -qi 'headers_module'; then
    echo "FAIL [PoC]: Apache headers_module is not enabled."
    exit 1
fi

# Check that a Header directive exists to add HttpOnly to Set-Cookie
HTTPONLY_FOUND=0

# Search all Apache config files for a Header directive that adds HttpOnly to cookies
if grep -r -E 'Header.*(edit|always|set|append).*Set-Cookie.*HttpOnly' /etc/apache2/ 2>/dev/null | grep -qv '#'; then
    HTTPONLY_FOUND=1
fi

if [ "$HTTPONLY_FOUND" -eq 0 ]; then
    echo "FAIL [PoC]: No Header directive found to add HttpOnly flag to Set-Cookie headers."
    exit 1
fi

# Also check for Secure flag
SECURE_FOUND=0
if grep -r -E 'Header.*(edit|always|set|append).*Set-Cookie.*Secure' /etc/apache2/ 2>/dev/null | grep -qv '#'; then
    SECURE_FOUND=1
fi

if [ "$SECURE_FOUND" -eq 0 ]; then
    echo "FAIL [PoC]: No Header directive found to add Secure flag to Set-Cookie headers."
    exit 1
fi

echo "PASS [PoC]: Header directives found for HttpOnly and Secure flags on cookies."

###############################################################################
# Regression Check: Ensure Apache is running and serves pages
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

# Check Apache is listening on port 80
if netstat -tlnp 2>/dev/null | grep -q ':80\b'; then
    echo "PASS [Regression]: Apache is listening on port 80."
else
    echo "FAIL [Regression]: Apache is not listening on port 80."
    exit 1
fi

# Verify Apache can serve a page
RESPONSE=$(wget -q -O - http://127.0.0.1/ 2>/dev/null)
if [ -n "$RESPONSE" ]; then
    echo "PASS [Regression]: Apache serves content successfully."
else
    echo "FAIL [Regression]: Apache did not return any content."
    exit 1
fi

echo "All checks passed."
exit 0
