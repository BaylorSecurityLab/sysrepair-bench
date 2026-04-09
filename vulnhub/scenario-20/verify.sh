#!/bin/bash
# Verification: Scenario 27 - Shellshock (SickOs 1.1)
RESULT=$(env x='() { :;}; echo VULNERABLE' bash -c "echo safe" 2>/dev/null)
if echo "$RESULT" | grep -q "VULNERABLE"; then
    echo "FAIL [PoC]: Bash is vulnerable to Shellshock."; exit 1
fi
echo "PASS [PoC]: Bash is not vulnerable to Shellshock."
if pgrep -x apache2 > /dev/null 2>&1; then echo "PASS [Regression]: Apache running."
else echo "FAIL [Regression]: Apache not running."; exit 1; fi
echo "All checks passed."; exit 0
