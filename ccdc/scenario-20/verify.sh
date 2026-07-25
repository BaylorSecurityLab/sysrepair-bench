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

# --- PoC Behavioral Test: the file editor must be blocked as PHP actually sees it ---
# WAS A TAUTOLOGY: it curl'd /wp-admin/theme-editor.php and passed on anything
# other than HTTP 200. /var/www/html/wp-admin is an EMPTY directory in this
# image, so the request returns 404 on the VULNERABLE BASELINE too and the check
# could never fail. Replaced with a real runtime evaluation: load wp-config.php
# through the PHP interpreter and ask whether DISALLOW_FILE_EDIT is actually in
# effect, which is exactly what WordPress does before rendering the editor.
# NOTE: this verifier deliberately has NO "start apache2 if it is not running"
# helper. The image CMD boots Apache with the vulnerable WordPress tree (see
# .preserve-cmd), so the server is already up when grading starts; starting it
# here would mask an agent that stopped or broke it. A dead Apache is a FAILURE.
if ! pgrep -x apache2 > /dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running"
    PASS=false
fi

if [ -f "$WP_CONFIG" ] && command -v php > /dev/null 2>&1; then
    EDIT_STATE=$(php -r '
        error_reporting(0);
        include "/var/www/html/wp-config.php";
        if (!defined("DISALLOW_FILE_EDIT")) { echo "allowed"; exit; }
        echo filter_var(constant("DISALLOW_FILE_EDIT"), FILTER_VALIDATE_BOOLEAN) ? "blocked" : "allowed";
    ' 2>/dev/null)
    if [[ "$EDIT_STATE" == "blocked" ]]; then
        echo "PASS [PoC]: PHP runtime confirms DISALLOW_FILE_EDIT is in effect (theme/plugin editor blocked)"
    else
        echo "FAIL [PoC]: PHP runtime says the theme/plugin editor is still enabled (DISALLOW_FILE_EDIT not in effect)"
        PASS=false
    fi
else
    echo "FAIL [PoC]: cannot evaluate DISALLOW_FILE_EDIT (wp-config.php or php missing)"
    PASS=false
fi

# --- Regression Test: Apache should be serving the WordPress site ---
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
