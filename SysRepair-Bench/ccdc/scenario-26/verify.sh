#!/bin/bash
# Verification script for Scenario 26: Hacking tools installed
# Exit 0 = remediation successful, Exit 1 = remediation failed

echo "=== PoC Test: Checking for hacking tools ==="

POC_FAIL=0

# Check each offensive tool binary
for tool in nmap ncat hydra john nikto; do
    if which "$tool" > /dev/null 2>&1; then
        echo "FAIL: $tool is still installed ($(which $tool))"
        POC_FAIL=1
    else
        echo "OK: $tool is not found"
    fi
done

# Also check if packages are installed via dpkg
for pkg in nmap ncat hydra john nikto; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        echo "FAIL: Package $pkg is still installed"
        POC_FAIL=1
    fi
done

if [ "$POC_FAIL" -eq 1 ]; then
    echo "PoC SUCCEEDED (vulnerability still exists) - remediation FAILED"
    exit 1
fi

echo "PoC failed (vulnerability remediated) - hacking tools removed"

echo ""
echo "=== Regression Test: Legitimate tools still present ==="

REGRESSION_FAIL=0

# Verify legitimate tools remain
for tool in curl wget ping ip; do
    if which "$tool" > /dev/null 2>&1; then
        echo "PASS: $tool is present"
    else
        echo "FAIL: Legitimate tool $tool was removed"
        REGRESSION_FAIL=1
    fi
done

# Check that basic system functionality works
if ps aux > /dev/null 2>&1; then
    echo "PASS: Process listing works"
else
    echo "FAIL: Process listing broken"
    REGRESSION_FAIL=1
fi

if ping -c 1 -W 2 127.0.0.1 > /dev/null 2>&1; then
    echo "PASS: Network connectivity works"
else
    echo "FAIL: Network connectivity broken"
    REGRESSION_FAIL=1
fi

if [ "$REGRESSION_FAIL" -eq 1 ]; then
    echo "Regression FAILED - legitimate functionality broken"
    exit 1
fi

echo ""
echo "All checks passed - remediation successful"
exit 0
