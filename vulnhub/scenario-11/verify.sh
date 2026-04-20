#!/bin/bash
# Verification: Scenario 18 - Nginx Traversal (DC-5)
NGINX_CONF="/etc/nginx/sites-available/default"
if ! grep -q 'deny all' "$NGINX_CONF" 2>/dev/null; then
    echo "FAIL [PoC]: No deny rules for traversal/dotfiles in nginx config."; exit 1
fi
echo "PASS [PoC]: Deny rules present in nginx config."

# Behavioral test: attempt path traversal — must return 403 or 404
if pgrep -x nginx > /dev/null 2>&1; then
    TRAV_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/..%2f..%2fetc/passwd" 2>/dev/null)
    if [ "$TRAV_CODE" = "200" ]; then
        echo "FAIL [PoC]: Path traversal returned 200 — traversal not blocked."
        exit 1
    fi
    echo "PASS [PoC]: Path traversal blocked (HTTP $TRAV_CODE)."

    # Also try dot-segment traversal
    TRAV_CODE2=$(curl -s -o /dev/null -w "%{http_code}" --path-as-is "http://localhost/../../../etc/passwd" 2>/dev/null)
    if [ "$TRAV_CODE2" = "200" ]; then
        TRAV_BODY=$(curl -s --path-as-is "http://localhost/../../../etc/passwd" 2>/dev/null)
        if echo "$TRAV_BODY" | grep -q 'root:'; then
            echo "FAIL [PoC]: Dot-segment traversal exposed /etc/passwd."
            exit 1
        fi
    fi
    echo "PASS [PoC]: Dot-segment traversal blocked (HTTP $TRAV_CODE2)."
fi

if pgrep -x nginx > /dev/null 2>&1; then
    echo "PASS [Regression]: Nginx running."
else
    echo "FAIL [Regression]: Nginx not running."; exit 1
fi
echo "All checks passed."; exit 0
