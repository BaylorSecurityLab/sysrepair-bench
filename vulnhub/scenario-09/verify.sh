#!/bin/bash
# Verification: Scenario 16 - PHP Command Injection (DC-4)
CMD_PHP="/var/www/html/cmd.php"
if [ ! -f "$CMD_PHP" ]; then
    echo "PASS [PoC]: cmd.php removed."; 
else
    if grep -q 'escapeshellarg\|escapeshellcmd' "$CMD_PHP"; then
        echo "PASS [PoC]: cmd.php uses input sanitization."
    else
        if grep -q 'system\|exec\|passthru\|shell_exec' "$CMD_PHP"; then
            echo "FAIL [PoC]: cmd.php calls system commands without sanitization."; exit 1
        fi
    fi
fi

# Behavioral test: attempt command injection via POST — must be blocked
if pgrep -x apache2 > /dev/null 2>&1; then
    CMD_OUT=$(curl -s -d "cmd=id" "http://localhost/cmd.php" 2>/dev/null)
    if echo "$CMD_OUT" | grep -q 'uid='; then
        echo "FAIL [PoC]: Command injection via POST succeeded — 'id' command ran."
        exit 1
    fi
    echo "PASS [PoC]: Command injection via POST blocked."
fi

if pgrep -x apache2 > /dev/null 2>&1; then
    echo "PASS [Regression]: Apache running."
else
    echo "FAIL [Regression]: Apache not running."; exit 1
fi
echo "All checks passed."; exit 0
