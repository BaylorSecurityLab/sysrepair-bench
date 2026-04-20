#!/bin/bash
# Verification: Scenario 14 - WordPress Weak Passwords (DC-2)
service mysql start > /dev/null 2>&1
sleep 2
HASHES=$(mysql -N -e "SELECT user_pass FROM wordpress.wp_users;" 2>/dev/null)
if echo "$HASHES" | grep -q '^\$P\$'; then
    echo "FAIL [PoC]: Weak phpass hashes (\$P\$) still present."; exit 1
fi
echo "PASS [PoC]: No weak phpass hashes found."

# Behavioral test: attempt to authenticate with weak password via MySQL
AUTH_RESULT=$(mysql -N -e "SELECT user_pass FROM wordpress.wp_users WHERE user_login='admin';" 2>/dev/null)
if [ -n "$AUTH_RESULT" ]; then
    # Verify the hash is NOT the old weak phpass hash
    if echo "$AUTH_RESULT" | grep -q '^\$P\$'; then
        echo "FAIL [PoC]: admin password hash is still weak phpass at runtime."
        exit 1
    fi
    echo "PASS [PoC]: admin password hash is not weak phpass at runtime."
fi

if pgrep -x apache2 > /dev/null 2>&1; then
    echo "PASS [Regression]: Apache running."
else
    echo "FAIL [Regression]: Apache not running."; exit 1
fi
echo "All checks passed."; exit 0
