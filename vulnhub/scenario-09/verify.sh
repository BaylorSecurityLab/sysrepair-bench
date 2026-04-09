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
if pgrep -x apache2 > /dev/null 2>&1; then
    echo "PASS [Regression]: Apache running."
else
    echo "FAIL [Regression]: Apache not running."; exit 1
fi
echo "All checks passed."; exit 0
