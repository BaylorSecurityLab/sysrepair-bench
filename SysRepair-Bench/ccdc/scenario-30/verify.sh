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
    echo "FAIL [PoC]: fail2ban is not running"
    PASS=false
fi

# --- PoC Test: SSH jail should be enabled ---
if [ -f /etc/fail2ban/jail.local ] || [ -f /etc/fail2ban/jail.d/sshd.conf ]; then
    if fail2ban-client status sshd 2>/dev/null | grep -q "Status"; then
        echo "PASS [PoC]: SSH jail is active in fail2ban"
    else
        # Check config file
        if grep -rqE '^\[sshd\]' /etc/fail2ban/jail.local /etc/fail2ban/jail.d/ 2>/dev/null; then
            echo "PASS [PoC]: SSH jail is configured"
        else
            echo "FAIL [PoC]: SSH jail is not configured"
            PASS=false
        fi
    fi
else
    echo "FAIL [PoC]: No fail2ban jail configuration found"
    PASS=false
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
