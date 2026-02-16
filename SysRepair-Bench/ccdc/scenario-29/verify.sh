#!/bin/bash
# Scenario 29: No firewall installed
# Verification: PoC should fail (firewall active) AND functionality test should pass

PASS=true

# --- PoC Test: ufw or iptables firewall should be installed and active ---
if command -v ufw > /dev/null 2>&1; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    if echo "$UFW_STATUS" | grep -qi "active"; then
        echo "PASS [PoC]: ufw is installed and active"
    else
        echo "FAIL [PoC]: ufw is installed but not active ($UFW_STATUS)"
        PASS=false
    fi
elif command -v iptables > /dev/null 2>&1; then
    RULES=$(iptables -L -n 2>/dev/null | grep -c -v '^Chain\|^target\|^$')
    if [ "$RULES" -gt 0 ]; then
        echo "PASS [PoC]: iptables has firewall rules configured"
    else
        echo "FAIL [PoC]: iptables installed but no rules configured"
        PASS=false
    fi
else
    echo "FAIL [PoC]: No firewall (ufw or iptables) is installed"
    PASS=false
fi

# --- PoC Test: Default policy should deny incoming ---
if command -v ufw > /dev/null 2>&1; then
    DEFAULT=$(ufw status verbose 2>/dev/null | grep "Default:")
    if echo "$DEFAULT" | grep -qi "deny (incoming)"; then
        echo "PASS [PoC]: Default incoming policy is deny"
    elif echo "$DEFAULT" | grep -qi "reject (incoming)"; then
        echo "PASS [PoC]: Default incoming policy is reject"
    else
        echo "FAIL [PoC]: Default incoming policy is not deny/reject"
        PASS=false
    fi
fi

# --- Regression Test: SSH and web server should be accessible ---
if pgrep -x sshd > /dev/null 2>&1 || pgrep -x nginx > /dev/null 2>&1; then
    echo "PASS [Regression]: Services are running"
else
    echo "FAIL [Regression]: Expected services are not running"
    PASS=false
fi

# Check that SSH is allowed through firewall
if command -v ufw > /dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -qE '22.*ALLOW|SSH.*ALLOW|OpenSSH.*ALLOW'; then
        echo "PASS [Regression]: SSH is allowed through firewall"
    else
        echo "FAIL [Regression]: SSH may not be allowed through firewall"
        PASS=false
    fi
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
