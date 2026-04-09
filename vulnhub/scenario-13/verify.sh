#!/bin/bash
# Verification: Scenario 20 - Drupal 8 Outdated (DC-7)
VERSION=$(grep -oP "VERSION = '\\K[^']+" /var/www/html/core/lib/Drupal.php 2>/dev/null || cat /var/www/html/core/VERSION.txt 2>/dev/null)
MAJOR=$(echo "$VERSION" | cut -d. -f2)
if [ -n "$MAJOR" ] && [ "$MAJOR" -lt 6 ] 2>/dev/null; then
    echo "FAIL [PoC]: Drupal version $VERSION is outdated (< 8.6.x)."; exit 1
fi
echo "PASS [PoC]: Drupal version $VERSION is acceptable."
if pgrep -x apache2 > /dev/null 2>&1; then
    echo "PASS [Regression]: Apache running."
else
    echo "FAIL [Regression]: Apache not running."; exit 1
fi
echo "All checks passed."; exit 0
