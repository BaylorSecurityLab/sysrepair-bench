#!/bin/bash
# Scenario 19: PHP dangerous functions enabled
# Verification: PoC should fail (functions disabled) AND functionality test should pass

PASS=true

# Find the active PHP ini file
PHP_INI=$(php -r "echo php_ini_loaded_file();" 2>/dev/null)
FPM_INIS=$(ls /etc/php/*/fpm/php.ini 2>/dev/null)

# NOTE: every config loop below used to `break` after the first ini, so only the
# CLI ini was ever inspected and the FPM ini (the one the web tier actually
# uses) was never config-checked. The `break`s are gone; all inis are checked.

# --- PoC Test: Dangerous functions should be disabled ---
for ini in $PHP_INI $FPM_INIS; do
    [ -f "$ini" ] || continue
    DISABLED=$(grep -E '^\s*disable_functions' "$ini" | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
    if [ -z "$DISABLED" ] || [ "$DISABLED" = "" ]; then
        echo "FAIL [PoC]: disable_functions is empty in $ini"
        PASS=false
    elif echo "$DISABLED" | grep -qE 'exec|system|passthru|shell_exec'; then
        echo "PASS [PoC]: Dangerous functions are disabled in $ini"
    else
        echo "FAIL [PoC]: Key dangerous functions not in disable_functions in $ini"
        PASS=false
    fi
done

# --- PoC Test: allow_url_include should be Off ---
for ini in $PHP_INI $FPM_INIS; do
    [ -f "$ini" ] || continue
    URL_INCLUDE=$(grep -E '^\s*allow_url_include' "$ini" | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
    if [[ "$URL_INCLUDE" == "On" ]] || [[ "$URL_INCLUDE" == "on" ]] || [[ "$URL_INCLUDE" == "1" ]]; then
        echo "FAIL [PoC]: allow_url_include is still On in $ini"
        PASS=false
    else
        echo "PASS [PoC]: allow_url_include is Off in $ini"
    fi
done

# --- PoC Test: expose_php should be Off ---
for ini in $PHP_INI $FPM_INIS; do
    [ -f "$ini" ] || continue
    EXPOSE=$(grep -E '^\s*expose_php' "$ini" | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
    if [[ "$EXPOSE" == "On" ]] || [[ "$EXPOSE" == "on" ]] || [[ "$EXPOSE" == "1" ]]; then
        echo "FAIL [PoC]: expose_php is still On in $ini"
        PASS=false
    else
        echo "PASS [PoC]: expose_php is Off in $ini"
    fi
done

# --- PoC Behavioral Test: Verify dangerous functions are disabled at runtime ---
EXEC_TEST=$(php -r "echo function_exists('exec') ? 'enabled' : 'disabled';" 2>/dev/null || true)
if [[ "$EXEC_TEST" == "enabled" ]]; then
    echo "FAIL [PoC]: exec() is still callable at PHP runtime"
    PASS=false
elif [[ "$EXEC_TEST" == "disabled" ]]; then
    echo "PASS [PoC]: exec() is disabled at PHP runtime"
fi

SYSTEM_TEST=$(php -r "echo function_exists('system') ? 'enabled' : 'disabled';" 2>/dev/null || true)
if [[ "$SYSTEM_TEST" == "enabled" ]]; then
    echo "FAIL [PoC]: system() is still callable at PHP runtime"
    PASS=false
elif [[ "$SYSTEM_TEST" == "disabled" ]]; then
    echo "PASS [PoC]: system() is disabled at PHP runtime"
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
# A dead nginx or php-fpm is a FAILURE.
FPM_SOCK=$(grep -hE '^[[:space:]]*listen[[:space:]]*=' /etc/php/*/fpm/pool.d/*.conf 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
if [ -n "$FPM_SOCK" ] && [ ! -S "$FPM_SOCK" ]; then
    echo "FAIL [Regression]: php-fpm is not listening on $FPM_SOCK"
    PASS=false
fi

if ! pgrep -x nginx > /dev/null 2>&1; then
    echo "FAIL [PoC]: nginx is not running, cannot evaluate X-Powered-By header"
    PASS=false
elif ! command -v curl > /dev/null 2>&1; then
    echo "FAIL [PoC]: curl is unavailable, cannot evaluate X-Powered-By header"
    PASS=false
else
    PHP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://localhost/index.php 2>/dev/null)
    if [[ "$PHP_CODE" != "200" ]]; then
        # Absence of the header only means something when PHP actually ran.
        echo "FAIL [PoC]: /index.php returned HTTP $PHP_CODE - PHP did not execute, header check is not meaningful"
        PASS=false
    else
        XPOWERED=$(curl -sI http://localhost/index.php 2>/dev/null | grep -i '^X-Powered-By:' || true)
        if echo "$XPOWERED" | grep -qi 'PHP'; then
            echo "FAIL [PoC]: X-Powered-By header exposes PHP version: $XPOWERED"
            PASS=false
        else
            echo "PASS [PoC]: PHP served HTTP 200 and no X-Powered-By header is exposed"
        fi
    fi
fi

# --- Regression Test: PHP should still execute ---
RESULT=$(php -r "echo 'PHP_OK';" 2>/dev/null)
if [[ "$RESULT" == "PHP_OK" ]]; then
    echo "PASS [Regression]: PHP CLI is functional"
else
    echo "FAIL [Regression]: PHP CLI is not functional"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
