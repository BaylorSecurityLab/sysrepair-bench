#!/bin/bash
# Verification: Scenario 20 - Drupal 8 Outdated (DC-7)
VERSION=$(grep -oP "VERSION = '\\K[^']+" /var/www/html/core/lib/Drupal.php 2>/dev/null || cat /var/www/html/core/VERSION.txt 2>/dev/null)
MAJOR=$(echo "$VERSION" | cut -d. -f2)
if [ -n "$MAJOR" ] && [ "$MAJOR" -lt 6 ] 2>/dev/null; then
    echo "FAIL [PoC]: Drupal version $VERSION is outdated (< 8.6.x)."; exit 1
fi
echo "PASS [PoC]: Drupal version $VERSION is acceptable."

# Behavioral test: CHANGELOG.txt should not expose a vulnerable version
if pgrep -x apache2 > /dev/null 2>&1; then
    CHANGELOG_VER=$(curl -s "http://localhost/core/CHANGELOG.txt" 2>/dev/null | head -5 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$CHANGELOG_VER" ]; then
        CL_MINOR=$(echo "$CHANGELOG_VER" | cut -d. -f2)
        if [ "$CL_MINOR" -lt 6 ] 2>/dev/null; then
            echo "FAIL [PoC]: CHANGELOG.txt reports vulnerable version $CHANGELOG_VER."
            exit 1
        fi
        echo "PASS [PoC]: CHANGELOG.txt reports version $CHANGELOG_VER (>= 8.6.x)."
    else
        # CHANGELOG.txt not accessible or doesn't show version — acceptable
        echo "PASS [PoC]: CHANGELOG.txt not exposing vulnerable version."
    fi
fi

if pgrep -x apache2 > /dev/null 2>&1; then
    echo "PASS [Regression]: Apache running."
else
    echo "FAIL [Regression]: Apache not running."; exit 1
fi
echo "All checks passed."; exit 0
