#!/bin/bash
# Scenario 05: SSH password auth with no key restriction
# Verification: PoC should fail (pubkey enabled) AND functionality test should pass

PASS=true

# --- PoC Test: PubkeyAuthentication should be enabled ---
PUBKEY=$(sshd -T 2>/dev/null | grep -i "^pubkeyauthentication" | awk '{print $2}')
if [ -z "$PUBKEY" ]; then
    PUBKEY=$(grep -i "^PubkeyAuthentication" /etc/ssh/sshd_config | tail -1 | awk '{print $2}')
fi

if [[ "$PUBKEY" == "no" ]]; then
    echo "FAIL [PoC]: PubkeyAuthentication is still disabled"
    PASS=false
else
    echo "PASS [PoC]: PubkeyAuthentication is enabled"
fi

# --- PoC Test: Password-only auth should not be the sole method ---
# At minimum, pubkey should be enabled. Ideally password auth is disabled.
PWAUTH=$(sshd -T 2>/dev/null | grep -i "^passwordauthentication" | awk '{print $2}')
if [ -z "$PWAUTH" ]; then
    PWAUTH=$(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config | tail -1 | awk '{print $2}')
fi

if [[ "$PUBKEY" != "no" ]] && [[ "$PWAUTH" == "no" ]]; then
    echo "PASS [PoC]: PasswordAuthentication disabled, PubkeyAuthentication enabled (ideal)"
elif [[ "$PUBKEY" != "no" ]]; then
    echo "PASS [PoC]: PubkeyAuthentication enabled (password auth still on but acceptable)"
else
    echo "FAIL [PoC]: System still relies on password-only authentication"
    PASS=false
fi

# --- PoC Behavioral Test: Verify password-only login behavior ---
# Ensure sshd is running for behavioral test
if ! pgrep -x sshd > /dev/null 2>&1; then
    /usr/sbin/sshd 2>/dev/null
    sleep 1
fi

if command -v sshpass > /dev/null 2>&1; then
    # If PasswordAuthentication is disabled, password-only SSH should fail
    if [[ "$PWAUTH" == "no" ]]; then
        PWD_RESULT=$(sshpass -p 'password123' ssh -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o ConnectTimeout=5 sysadmin@127.0.0.1 echo ok 2>&1 || true)
        if [[ "$PWD_RESULT" == "ok" ]]; then
            echo "FAIL [PoC]: Password-only login succeeded despite PasswordAuthentication=no"
            PASS=false
        else
            echo "PASS [PoC]: Password-only login correctly denied"
        fi
    else
        echo "INFO [PoC]: PasswordAuthentication is still on; password-only login test skipped"
    fi
else
    echo "INFO [PoC]: sshpass not available, skipping behavioral password-only login test"
fi

# --- Regression Test: SSH service should still be functional ---
if pgrep -x sshd > /dev/null 2>&1; then
    echo "PASS [Regression]: sshd process is running"
else
    /usr/sbin/sshd 2>/dev/null
    if pgrep -x sshd > /dev/null 2>&1; then
        echo "PASS [Regression]: sshd started successfully"
    else
        echo "FAIL [Regression]: sshd is not running and cannot be started"
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
