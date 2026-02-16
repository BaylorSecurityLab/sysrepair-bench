#!/bin/bash
# Scenario 49: Rogue SSH authorized_keys on root
# Verification: PoC should fail (rogue keys removed) AND functionality test should pass

PASS=true

# --- PoC Test: Root should not have unauthorized authorized_keys ---
if [ -f /root/.ssh/authorized_keys ]; then
    # Check for known rogue keys
    if grep -q 'attacker@evil.com' /root/.ssh/authorized_keys 2>/dev/null; then
        echo "FAIL [PoC]: Rogue key 'attacker@evil.com' still in root authorized_keys"
        PASS=false
    else
        echo "PASS [PoC]: Rogue key 'attacker@evil.com' removed"
    fi

    if grep -q 'backdoor@malware.net' /root/.ssh/authorized_keys 2>/dev/null; then
        echo "FAIL [PoC]: Rogue key 'backdoor@malware.net' still in root authorized_keys"
        PASS=false
    else
        echo "PASS [PoC]: Rogue key 'backdoor@malware.net' removed"
    fi

    # Check if file is empty or removed
    KEY_COUNT=$(grep -c 'ssh-' /root/.ssh/authorized_keys 2>/dev/null)
    if [ "$KEY_COUNT" -gt 0 ]; then
        echo "WARNING: $KEY_COUNT SSH key(s) remain in root authorized_keys - verify they are legitimate"
    fi
else
    echo "PASS [PoC]: /root/.ssh/authorized_keys does not exist (all keys removed)"
fi

# --- PoC Test: Check other users' authorized_keys too ---
ROGUE_FOUND=false
for home_dir in /home/*/; do
    user=$(basename "$home_dir")
    ak_file="$home_dir.ssh/authorized_keys"
    if [ -f "$ak_file" ]; then
        if grep -qE 'attacker|backdoor|evil\.com|malware\.net' "$ak_file" 2>/dev/null; then
            echo "FAIL [PoC]: Rogue key found in $ak_file"
            ROGUE_FOUND=true
            PASS=false
        fi
    fi
done
if ! $ROGUE_FOUND; then
    echo "PASS [PoC]: No rogue keys found in user authorized_keys files"
fi

# --- Regression Test: SSH should still be functional ---
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

# Check user still exists
if id sysadmin > /dev/null 2>&1; then
    echo "PASS [Regression]: sysadmin user still exists"
else
    echo "FAIL [Regression]: sysadmin user is missing"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
