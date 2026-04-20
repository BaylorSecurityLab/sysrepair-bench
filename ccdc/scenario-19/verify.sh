#!/bin/bash
# Scenario 19: PHP dangerous functions enabled
# Verification: PoC should fail (functions disabled) AND functionality test should pass

PASS=true

# Find the active PHP ini file
PHP_INI=$(php -r "echo php_ini_loaded_file();" 2>/dev/null)
FPM_INIS=$(ls /etc/php/*/fpm/php.ini 2>/dev/null)

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
    break
done

# --- PoC Test: allow_url_include should be Off ---
for ini in $PHP_INI $FPM_INIS; do
    [ -f "$ini" ] || continue
    URL_INCLUDE=$(grep -E '^\s*allow_url_include' "$ini" | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
    if [[ "$URL_INCLUDE" == "On" ]] || [[ "$URL_INCLUDE" == "on" ]] || [[ "$URL_INCLUDE" == "1" ]]; then
        echo "FAIL [PoC]: allow_url_include is still On in $ini"
        PASS=false
    else
        echo "PASS [PoC]: allow_url_include is Off"
    fi
    break
done

# --- PoC Test: expose_php should be Off ---
for ini in $PHP_INI $FPM_INIS; do
    [ -f "$ini" ] || continue
    EXPOSE=$(grep -E '^\s*expose_php' "$ini" | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
    if [[ "$EXPOSE" == "On" ]] || [[ "$EXPOSE" == "on" ]] || [[ "$EXPOSE" == "1" ]]; then
        echo "FAIL [PoC]: expose_php is still On"
        PASS=false
    else
        echo "PASS [PoC]: expose_php is Off"
    fi
    break
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
# Start PHP-FPM and nginx if not running
if ! pgrep -x nginx > /dev/null 2>&1; then
    service $(ls /etc/init.d/ 2>/dev/null | grep php.*fpm | head -1) start 2>/dev/null || true
    nginx 2>/dev/null || true
    sleep 1
fi

if pgrep -x nginx > /dev/null 2>&1 && command -v curl > /dev/null 2>&1; then
    XPOWERED=$(curl -sI http://localhost/index.php 2>/dev/null | grep -i '^X-Powered-By:' || true)
    if echo "$XPOWERED" | grep -qi 'PHP'; then
        echo "FAIL [PoC]: X-Powered-By header exposes PHP version: $XPOWERED"
        PASS=false
    else
        echo "PASS [PoC]: X-Powered-By header does not expose PHP"
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
