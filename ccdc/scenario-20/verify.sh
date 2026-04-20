#!/bin/bash
# Scenario 20: WordPress file editor enabled
# Verification: PoC should fail (file editor disabled) AND functionality test should pass

PASS=true

WP_CONFIG="/var/www/html/wp-config.php"

# --- PoC Test: DISALLOW_FILE_EDIT should be true ---
if [ -f "$WP_CONFIG" ]; then
    if grep -q "DISALLOW_FILE_EDIT.*true" "$WP_CONFIG" 2>/dev/null; then
        echo "PASS [PoC]: DISALLOW_FILE_EDIT is set to true"
    else
        echo "FAIL [PoC]: DISALLOW_FILE_EDIT is not set to true"
        PASS=false
    fi
else
    echo "FAIL [PoC]: wp-config.php not found"
    PASS=false
fi

# --- PoC Test: wp-config.php should have restrictive permissions ---
if [ -f "$WP_CONFIG" ]; then
    PERMS=$(stat -c "%a" "$WP_CONFIG" 2>/dev/null)
    # Should be 440 or 400 (read-only)
    if [[ "$PERMS" == "440" ]] || [[ "$PERMS" == "400" ]] || [[ "$PERMS" == "444" ]]; then
        echo "PASS [PoC]: wp-config.php has restrictive permissions ($PERMS)"
    else
        echo "FAIL [PoC]: wp-config.php has loose permissions ($PERMS, should be 440)"
        PASS=false
    fi
fi

# --- PoC Behavioral Test: Theme/plugin editor endpoint should not be accessible ---
# Start Apache if not running
if ! pgrep -x apache2 > /dev/null 2>&1; then
    apachectl start 2>/dev/null
    sleep 1
fi

if command -v curl > /dev/null 2>&1; then
    EDITOR_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://localhost/wp-admin/theme-editor.php 2>/dev/null || true)
    if [[ "$EDITOR_CODE" == "200" ]]; then
        echo "FAIL [PoC]: wp-admin/theme-editor.php returns HTTP 200 (editor may be accessible)"
        PASS=false
    else
        echo "PASS [PoC]: wp-admin/theme-editor.php returns HTTP $EDITOR_CODE (not directly accessible)"
    fi
fi

# --- Regression Test: Apache should be serving the WordPress site ---
if ! pgrep -x apache2 > /dev/null 2>&1; then
    apachectl start 2>/dev/null
    sleep 1
fi

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    echo "PASS [Regression]: Apache is serving WordPress (HTTP 200)"
else
    echo "FAIL [Regression]: Apache is not serving WordPress (HTTP $RESPONSE)"
    PASS=false
fi

# Check wp-config.php still has valid PHP syntax
if php -l "$WP_CONFIG" 2>/dev/null | grep -q "No syntax errors"; then
    echo "PASS [Regression]: wp-config.php has valid PHP syntax"
else
    echo "FAIL [Regression]: wp-config.php has syntax errors"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
