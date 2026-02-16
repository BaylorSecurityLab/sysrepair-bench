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
