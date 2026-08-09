#!/bin/bash
# Scenario 19: PHP dangerous functions enabled
# Verification: PoC should fail (functions disabled) AND functionality test should pass
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "hardened php.ini but killed nginx" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# Find the active PHP ini file
PHP_INI=$(php -r "echo php_ini_loaded_file();" 2>/dev/null)
FPM_INIS=$(ls /etc/php/*/fpm/php.ini 2>/dev/null)

# Per-ini check ids are derived from the ini path so each ini gets its own
# record rather than several checks colliding under one name.
ini_tag() { echo "$1" | sed -e 's|^/||' -e 's|[^A-Za-z0-9]|_|g'; }

# NOTE: every config loop below used to `break` after the first ini, so only the
# CLI ini was ever inspected and the FPM ini (the one the web tier actually
# uses) was never config-checked. The `break`s are gone; all inis are checked.

# --- PoC Test: Dangerous functions should be disabled ---
for ini in $PHP_INI $FPM_INIS; do
    [ -f "$ini" ] || continue
    TAG=$(ini_tag "$ini")
    DISABLED=$(grep -E '^\s*disable_functions' "$ini" | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
    if [ -z "$DISABLED" ] || [ "$DISABLED" = "" ]; then
        record_poc "disable_functions_set_${TAG}" 0 "disable_functions is empty in $ini"
    elif echo "$DISABLED" | grep -qE 'exec|system|passthru|shell_exec'; then
        record_poc "disable_functions_set_${TAG}" 1 "dangerous functions are disabled in $ini"
    else
        record_poc "disable_functions_set_${TAG}" 0 "key dangerous functions not in disable_functions in $ini"
    fi
done

# --- PoC Test: allow_url_include should be Off ---
for ini in $PHP_INI $FPM_INIS; do
    [ -f "$ini" ] || continue
    TAG=$(ini_tag "$ini")
    URL_INCLUDE=$(grep -E '^\s*allow_url_include' "$ini" | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
    if [[ "$URL_INCLUDE" == "On" ]] || [[ "$URL_INCLUDE" == "on" ]] || [[ "$URL_INCLUDE" == "1" ]]; then
        record_poc "allow_url_include_off_${TAG}" 0 "allow_url_include is still On in $ini"
    else
        record_poc "allow_url_include_off_${TAG}" 1 "allow_url_include is Off in $ini"
    fi
done

# --- PoC Test: expose_php should be Off ---
for ini in $PHP_INI $FPM_INIS; do
    [ -f "$ini" ] || continue
    TAG=$(ini_tag "$ini")
    EXPOSE=$(grep -E '^\s*expose_php' "$ini" | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
    if [[ "$EXPOSE" == "On" ]] || [[ "$EXPOSE" == "on" ]] || [[ "$EXPOSE" == "1" ]]; then
        record_poc "expose_php_off_${TAG}" 0 "expose_php is still On in $ini"
    else
        record_poc "expose_php_off_${TAG}" 1 "expose_php is Off in $ini"
    fi
done

# --- PoC Behavioral Test: Verify dangerous functions are disabled at runtime ---
EXEC_TEST=$(php -r "echo function_exists('exec') ? 'enabled' : 'disabled';" 2>/dev/null || true)
if [[ "$EXEC_TEST" == "enabled" ]]; then
    record_poc exec_disabled_at_runtime 0 "exec() is still callable at PHP runtime"
elif [[ "$EXEC_TEST" == "disabled" ]]; then
    record_poc exec_disabled_at_runtime 1
fi

SYSTEM_TEST=$(php -r "echo function_exists('system') ? 'enabled' : 'disabled';" 2>/dev/null || true)
if [[ "$SYSTEM_TEST" == "enabled" ]]; then
    record_poc system_disabled_at_runtime 0 "system() is still callable at PHP runtime"
elif [[ "$SYSTEM_TEST" == "disabled" ]]; then
    record_poc system_disabled_at_runtime 1
fi

# --- PoC Behavioral Test: Verify expose_php is Off via HTTP headers ---
# WAS BROKEN: this check PASSED on the vulnerable baseline with expose_php=On,
# because the request 502'd (the nginx vhost pointed at /run/php/php-fpm.sock
# while Ubuntu's pool creates /run/php/phpX.Y-fpm.sock) so the header was absent
# FOR THE WRONG REASON. It also silently skipped itself whenever nginx failed to
# start. Now: nginx not running is a hard FAIL, and the PHP endpoint must return
# HTTP 200 before the header verdict is trusted.
# NOTE: this verifier deliberately does NOT start php-fpm or nginx. The image
# CMD boots both with the vulnerable php.ini (see .preserve-cmd), so the web
# tier is already up when grading starts. Starting it here would (a) mask an
# agent that stopped or broke either daemon and (b) hide the "edited php.ini but
# never restarted php-fpm" mistake by spawning a pool that reads the fixed ini.
# A dead nginx or php-fpm is a FAILURE, recorded as a regression check.
FPM_SOCK=$(grep -hE '^[[:space:]]*listen[[:space:]]*=' /etc/php/*/fpm/pool.d/*.conf 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
if [ -n "$FPM_SOCK" ]; then
    if [ -S "$FPM_SOCK" ]; then
        record_reg php_fpm_listening 1 "php-fpm is listening on $FPM_SOCK"
    else
        record_reg php_fpm_listening 0 "php-fpm is not listening on $FPM_SOCK"
    fi
fi

# nginx liveness is a service-health fact, so it is recorded as a regression
# check. The header PoC below is only meaningful while the web tier is up; when
# it is down the PoC is unmeasurable and is deliberately not credited either way.
if pgrep -x nginx > /dev/null 2>&1; then
    record_reg nginx_running 1
else
    record_reg nginx_running 0 "nginx is not running"
fi

if ! pgrep -x nginx > /dev/null 2>&1; then
    echo "  [skip] nginx is not running - X-Powered-By header cannot be evaluated"
elif ! command -v curl > /dev/null 2>&1; then
    record_poc xpowered_by_hidden 0 "curl is unavailable, cannot evaluate X-Powered-By header"
else
    PHP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://localhost/index.php 2>/dev/null)
    if [[ "$PHP_CODE" != "200" ]]; then
        # Absence of the header only means something when PHP actually ran.
        record_poc xpowered_by_hidden 0 "/index.php returned HTTP $PHP_CODE - PHP did not execute, header check is not meaningful"
    else
        XPOWERED=$(curl -sI http://localhost/index.php 2>/dev/null | grep -i '^X-Powered-By:' || true)
        if echo "$XPOWERED" | grep -qi 'PHP'; then
            record_poc xpowered_by_hidden 0 "X-Powered-By header exposes PHP version: $XPOWERED"
        else
            record_poc xpowered_by_hidden 1 "PHP served HTTP 200 and no X-Powered-By header is exposed"
        fi
    fi
fi

# --- Regression Test: PHP should still execute ---
RESULT=$(php -r "echo 'PHP_OK';" 2>/dev/null)
if [[ "$RESULT" == "PHP_OK" ]]; then
    record_reg php_cli_functional 1
else
    record_reg php_cli_functional 0 "PHP CLI is not functional"
fi

verify_finish
