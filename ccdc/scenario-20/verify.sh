#!/bin/bash
# Scenario 20: WordPress file editor enabled
# Verification: PoC should fail (file editor disabled) AND functionality test should pass
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "disabled the editor but killed Apache" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

WP_CONFIG="/var/www/html/wp-config.php"

# --- PoC Test: DISALLOW_FILE_EDIT should be true ---
if [ -f "$WP_CONFIG" ]; then
    if grep -q "DISALLOW_FILE_EDIT.*true" "$WP_CONFIG" 2>/dev/null; then
        record_poc disallow_file_edit_configured 1 "DISALLOW_FILE_EDIT is set to true"
    else
        record_poc disallow_file_edit_configured 0 "DISALLOW_FILE_EDIT is not set to true"
    fi
else
    record_poc disallow_file_edit_configured 0 "wp-config.php not found"
fi

# --- PoC Test: wp-config.php should have restrictive permissions ---
if [ -f "$WP_CONFIG" ]; then
    PERMS=$(stat -c "%a" "$WP_CONFIG" 2>/dev/null)
    # Should be 440 or 400 (read-only)
    if [[ "$PERMS" == "440" ]] || [[ "$PERMS" == "400" ]] || [[ "$PERMS" == "444" ]]; then
        record_poc wp_config_perms_restrictive 1 "wp-config.php has restrictive permissions ($PERMS)"
    else
        record_poc wp_config_perms_restrictive 0 "wp-config.php has loose permissions ($PERMS, should be 440)"
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
if pgrep -x apache2 > /dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running"
fi

if [ -f "$WP_CONFIG" ] && command -v php > /dev/null 2>&1; then
    EDIT_STATE=$(php -r '
        error_reporting(0);
        include "/var/www/html/wp-config.php";
        if (!defined("DISALLOW_FILE_EDIT")) { echo "allowed"; exit; }
        echo filter_var(constant("DISALLOW_FILE_EDIT"), FILTER_VALIDATE_BOOLEAN) ? "blocked" : "allowed";
    ' 2>/dev/null)
    if [[ "$EDIT_STATE" == "blocked" ]]; then
        record_poc file_editor_blocked_at_runtime 1 "PHP runtime confirms DISALLOW_FILE_EDIT is in effect (theme/plugin editor blocked)"
    else
        record_poc file_editor_blocked_at_runtime 0 "PHP runtime says the theme/plugin editor is still enabled (DISALLOW_FILE_EDIT not in effect)"
    fi
else
    record_poc file_editor_blocked_at_runtime 0 "cannot evaluate DISALLOW_FILE_EDIT (wp-config.php or php missing)"
fi

# --- Regression Test: Apache should be serving the WordPress site ---
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    record_reg wordpress_served 1 "Apache is serving WordPress (HTTP 200)"
else
    record_reg wordpress_served 0 "Apache is not serving WordPress (HTTP $RESPONSE)"
fi

# Check wp-config.php still has valid PHP syntax
if php -l "$WP_CONFIG" 2>/dev/null | grep -q "No syntax errors"; then
    record_reg wp_config_syntax_valid 1
else
    record_reg wp_config_syntax_valid 0 "wp-config.php has syntax errors"
fi

verify_finish
