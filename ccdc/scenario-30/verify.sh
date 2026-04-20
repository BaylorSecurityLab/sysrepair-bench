#!/bin/bash
# Scenario 30: fail2ban not installed
# Verification: PoC should fail (fail2ban active) AND functionality test should pass

PASS=true

# --- PoC Test: fail2ban should be installed ---
if dpkg -l fail2ban 2>/dev/null | grep -q "^ii"; then
    echo "PASS [PoC]: fail2ban is installed"
else
    echo "FAIL [PoC]: fail2ban is not installed"
    PASS=false
fi

# --- PoC Test: fail2ban should be running ---
if pgrep -x fail2ban-server > /dev/null 2>&1 || pgrep -f fail2ban > /dev/null 2>&1; then
    echo "PASS [PoC]: fail2ban is running"
else
    # Try to start fail2ban
    fail2ban-server -b 2>/dev/null || fail2ban-client start 2>/dev/null || true
    sleep 1
    if pgrep -x fail2ban-server > /dev/null 2>&1 || pgrep -f fail2ban > /dev/null 2>&1; then
        echo "PASS [PoC]: fail2ban started successfully"
    else
        echo "FAIL [PoC]: fail2ban is not running and could not be started"
        PASS=false
    fi
fi

# --- PoC Primary Test: fail2ban-client status sshd should show active jail ---
F2B_STATUS=$(fail2ban-client status sshd 2>/dev/null || true)
if echo "$F2B_STATUS" | grep -q "Status"; then
    echo "PASS [PoC]: SSH jail is active (fail2ban-client status sshd confirms)"
    # Extract and report details
    TOTAL_BANNED=$(echo "$F2B_STATUS" | grep "Currently banned" | awk '{print $NF}')
    echo "INFO [PoC]: Currently banned IPs: ${TOTAL_BANNED:-0}"
else
    # Fallback: Check config files
    if [ -f /etc/fail2ban/jail.local ] || [ -f /etc/fail2ban/jail.d/sshd.conf ]; then
        if grep -rqE '^\[sshd\]' /etc/fail2ban/jail.local /etc/fail2ban/jail.d/ 2>/dev/null; then
            echo "FAIL [PoC]: SSH jail is configured but fail2ban-client cannot confirm it is active"
            PASS=false
        else
            echo "FAIL [PoC]: SSH jail is not configured in jail files"
            PASS=false
        fi
    else
        echo "FAIL [PoC]: No fail2ban jail configuration found and fail2ban-client reports no sshd jail"
        PASS=false
    fi
fi

# --- Regression Test: SSH should still be running ---
if pgrep -x sshd > /dev/null 2>&1; then
    echo "PASS [Regression]: sshd is running"
else
    /usr/sbin/sshd 2>/dev/null
    if pgrep -x sshd > /dev/null 2>&1; then
        echo "PASS [Regression]: sshd started successfully"
    else
        echo "FAIL [Regression]: sshd is not running"
        PASS=false
    fi
fi

if sshd -t 2>/dev/null; then
    echo "PASS [Regression]: sshd configuration is valid"
else
    echo "FAIL [Regression]: sshd configuration is invalid"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
