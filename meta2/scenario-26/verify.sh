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

echo "PASS [PoC]: Header directives found for HttpOnly and Secure flags on cookies (config check)."

# Behavioral test: check actual HTTP response headers for security flags
# Start Apache if not running
if ! pgrep -x apache2 > /dev/null 2>&1; then
    apache2ctl start > /dev/null 2>&1
    sleep 2
fi

if command -v curl > /dev/null 2>&1; then
    HEADERS=$(curl -sI http://127.0.0.1/ 2>/dev/null || true)
    if [ -n "$HEADERS" ]; then
        # Check for X-Frame-Options header
        if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
            echo "PASS [PoC]: X-Frame-Options header present (behavioral test)."
        else
            echo "WARN [PoC]: X-Frame-Options header not found in response."
        fi

        # Check for X-Content-Type-Options header
        if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
            echo "PASS [PoC]: X-Content-Type-Options header present (behavioral test)."
        else
            echo "WARN [PoC]: X-Content-Type-Options header not found in response."
        fi

        # Check Set-Cookie for HttpOnly and Secure flags (if cookies are set)
        COOKIE_HEADERS=$(echo "$HEADERS" | grep -i "Set-Cookie" || true)
        if [ -n "$COOKIE_HEADERS" ]; then
            if echo "$COOKIE_HEADERS" | grep -qi "HttpOnly"; then
                echo "PASS [PoC]: HttpOnly flag present on cookies (behavioral test)."
            else
                echo "FAIL [PoC]: Cookies set without HttpOnly flag (behavioral test)."
                exit 1
            fi
            if echo "$COOKIE_HEADERS" | grep -qi "Secure"; then
                echo "PASS [PoC]: Secure flag present on cookies (behavioral test)."
            else
                echo "FAIL [PoC]: Cookies set without Secure flag (behavioral test)."
                exit 1
            fi
        else
            echo "INFO [PoC]: No Set-Cookie headers in response (cookie flags will apply when cookies are set)."
        fi
    else
        echo "WARN [PoC]: Could not fetch headers from Apache."
    fi
elif command -v wget > /dev/null 2>&1; then
    HEADERS=$(wget -q -S -O /dev/null http://127.0.0.1/ 2>&1 || true)
    if echo "$HEADERS" | grep -qi "X-Frame-Options\|X-Content-Type\|HttpOnly"; then
        echo "PASS [PoC]: Security headers found in response (wget behavioral test)."
    else
        echo "WARN [PoC]: Security headers not detected via wget."
    fi
else
    echo "INFO [PoC]: Neither curl nor wget available; skipping header behavioral test."
fi

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
