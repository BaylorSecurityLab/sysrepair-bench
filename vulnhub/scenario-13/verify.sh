#!/bin/bash
# Verification: Scenario 13 - Drupal 8 outdated core (SA-CORE-2018-002/-004)
# VulnHub Source: DC-7
#
# PoC checks:        BOTH authoritative version sources report core >= 8.6.0
# Regression checks: both version sources are still present (the core files were
#                    upgraded, not deleted)
#
# Exit 0 = every check passed          (remediated, core files intact)
# Exit 1 = at least one check failed
#
# This scenario has no live service to exploit - the vulnerability is the core
# VERSION reported by the code. We read the version from BOTH authoritative
# sources (the Drupal::VERSION constant and core/VERSION.txt), parse it, and
# require a patched release. Matching both sources prevents a "fix one file"
# false pass.
#
# Two-component protocol: nothing aborts early. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

DRUPAL_PHP=/var/www/html/core/lib/Drupal.php
VERSION_TXT=/var/www/html/core/VERSION.txt

check_version() {  # $1 = id, $2 = version string, $3 = source label
    local id="$1" v="$2" src="$3" maj min
    if [ -z "$v" ]; then
        record_poc "$id" 0 "could not read a version from $src"
        return
    fi
    echo "  $src reports version: $v"
    maj=$(printf '%s' "$v" | cut -d. -f1)
    min=$(printf '%s' "$v" | cut -d. -f2)
    if ! printf '%s' "$maj" | grep -qE '^[0-9]+$' || ! printf '%s' "$min" | grep -qE '^[0-9]+$'; then
        record_poc "$id" 0 "$src version '$v' is not a parseable release number"
        return
    fi
    # Vulnerable if 8.0.x .. 8.5.x. Require >= 8.6.0 (or any major > 8).
    if [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "$min" -lt 6 ]; }; then
        record_poc "$id" 0 "$src reports $v (< 8.6.0) - still exposed to SA-CORE-2018-002/-004"
    else
        record_poc "$id" 1
    fi
}

# --- Regression: the core files must still exist (upgraded, not deleted) ---
if [ -f "$DRUPAL_PHP" ]; then
    record_reg drupal_php_present 1
else
    record_reg drupal_php_present 0 "$DRUPAL_PHP missing"
fi
if [ -f "$VERSION_TXT" ]; then
    record_reg version_txt_present 1
else
    record_reg version_txt_present 0 "$VERSION_TXT missing"
fi

PHP_VER=$(grep -oE "VERSION = '[^']+'" "$DRUPAL_PHP" 2>/dev/null | grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?" | head -1)
TXT_VER=$(grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?" "$VERSION_TXT" 2>/dev/null | head -1)

check_version drupal_php_version_patched "$PHP_VER" "Drupal::VERSION (Drupal.php)"
check_version version_txt_patched        "$TXT_VER" "core/VERSION.txt"

verify_finish
