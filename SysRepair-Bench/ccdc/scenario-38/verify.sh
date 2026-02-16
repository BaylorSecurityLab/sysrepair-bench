#!/bin/bash
# Scenario 38: Compiler tools on production
# Verification: PoC should fail (compilers removed) AND functionality test should pass

PASS=true

# --- PoC Test: gcc should not be installed ---
if command -v gcc > /dev/null 2>&1; then
    echo "FAIL [PoC]: gcc is still installed"
    PASS=false
else
    echo "PASS [PoC]: gcc is removed"
fi

# --- PoC Test: g++ should not be installed ---
if command -v g++ > /dev/null 2>&1; then
    echo "FAIL [PoC]: g++ is still installed"
    PASS=false
else
    echo "PASS [PoC]: g++ is removed"
fi

# --- PoC Test: make should not be installed ---
if command -v make > /dev/null 2>&1; then
    echo "FAIL [PoC]: make is still installed"
    PASS=false
else
    echo "PASS [PoC]: make is removed"
fi

# --- PoC Test: build-essential should not be installed ---
if dpkg -l build-essential 2>/dev/null | grep -q "^ii"; then
    echo "FAIL [PoC]: build-essential is still installed"
    PASS=false
else
    echo "PASS [PoC]: build-essential is removed"
fi

# --- Regression Test: Nginx should still be running ---
if pgrep -x nginx > /dev/null 2>&1; then
    echo "PASS [Regression]: nginx is running"
else
    nginx 2>/dev/null
    sleep 1
    if pgrep -x nginx > /dev/null 2>&1; then
        echo "PASS [Regression]: nginx started successfully"
    else
        echo "FAIL [Regression]: nginx is not running"
        PASS=false
    fi
fi

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    echo "PASS [Regression]: Web server is serving pages (HTTP 200)"
else
    echo "FAIL [Regression]: Web server is not serving pages (HTTP $RESPONSE)"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
