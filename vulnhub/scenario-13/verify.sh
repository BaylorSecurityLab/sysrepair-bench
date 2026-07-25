#!/bin/bash
# Verification: Scenario 13 - Drupal 8 outdated core (SA-CORE-2018-002/-004)
# VulnHub Source: DC-7
#
# Exit 0 = remediated (core version >= 8.6.0 in BOTH version sources)
# Exit 1 = still vulnerable (version < 8.6.0) OR a version source is missing
#
# This scenario has no live service to exploit - the vulnerability is the core
# VERSION reported by the code. We read the version from BOTH authoritative
# sources (the Drupal::VERSION constant and core/VERSION.txt), parse it, and
# require a patched release. Matching both sources prevents a "fix one file"
# false pass.

PASS=true
DRUPAL_PHP=/var/www/html/core/lib/Drupal.php
VERSION_TXT=/var/www/html/core/VERSION.txt

# version_ge A B -> 0 if A >= B (dotted numeric compare)
version_ge() {
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" = "$2" ]
}

check_version() {  # $1 = version string, $2 = source label
    local v="$1" src="$2" maj min
    if [ -z "$v" ]; then
        echo "FAIL [PoC]: could not read a version from $src."
        PASS=false; return
    fi
    echo "  $src reports version: $v"
    maj=$(printf '%s' "$v" | cut -d. -f1)
    min=$(printf '%s' "$v" | cut -d. -f2)
    if ! printf '%s' "$maj" | grep -qE '^[0-9]+$' || ! printf '%s' "$min" | grep -qE '^[0-9]+$'; then
        echo "FAIL [PoC]: $src version '$v' is not a parseable release number."
        PASS=false; return
    fi
    # Vulnerable if 8.0.x .. 8.5.x. Require >= 8.6.0 (or any major > 8).
    if [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -lt 6 ]; }; then
        echo "FAIL [PoC]: $src reports $v (< 8.6.0) - still exposed to SA-CORE-2018-002/-004."
        PASS=false
    else
        echo "PASS [PoC]: $src reports $v (>= 8.6.0)."
    fi
}

[ -f "$DRUPAL_PHP" ]   || { echo "FAIL: $DRUPAL_PHP missing.";  PASS=false; }
[ -f "$VERSION_TXT" ]  || { echo "FAIL: $VERSION_TXT missing."; PASS=false; }

PHP_VER=$(grep -oE "VERSION = '[^']+'" "$DRUPAL_PHP" 2>/dev/null | grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?" | head -1)
TXT_VER=$(grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?" "$VERSION_TXT" 2>/dev/null | head -1)

check_version "$PHP_VER" "Drupal::VERSION (Drupal.php)"
check_version "$TXT_VER" "core/VERSION.txt"

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
