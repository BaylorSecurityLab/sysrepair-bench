#!/bin/bash
# Verification: Scenario 18 - Nginx Traversal (DC-5)
NGINX_CONF="/etc/nginx/sites-available/default"
if ! grep -q 'deny all' "$NGINX_CONF" 2>/dev/null; then
    echo "FAIL [PoC]: No deny rules for traversal/dotfiles in nginx config."; exit 1
fi
echo "PASS [PoC]: Deny rules present in nginx config."
if pgrep -x nginx > /dev/null 2>&1; then
    echo "PASS [Regression]: Nginx running."
else
    echo "FAIL [Regression]: Nginx not running."; exit 1
fi
echo "All checks passed."; exit 0
