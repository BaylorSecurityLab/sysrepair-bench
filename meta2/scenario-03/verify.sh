#!/bin/bash
# Verification script for Scenario 03: SSH Default Credentials
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Ensure default credentials no longer work
###############################################################################

# We check this by verifying either:
# (a) PasswordAuthentication is disabled, OR
# (b) The known weak passwords have been changed

SSHD_CONFIG="/etc/ssh/sshd_config"

# Check if PasswordAuthentication is disabled (strongest fix)
PASS_AUTH=$(grep -i '^PasswordAuthentication' "$SSHD_CONFIG" | tail -1 | awk '{print $2}')

if [ "$PASS_AUTH" = "no" ]; then
    echo "PASS [PoC]: PasswordAuthentication is disabled — credential-based attacks blocked."
else
    # PasswordAuthentication is still enabled, so we must verify passwords were changed.
    # Check by attempting to validate known weak passwords against /etc/shadow.

    # We need a way to test passwords. Use a helper approach with su or sshpass if available.
    # Fallback: check /etc/shadow for password hash changes using python/perl crypt comparison.

    WEAK_FOUND=0

    for PAIR in "msfadmin:msfadmin" "user:user" "root:root"; do
        USERNAME=$(echo "$PAIR" | cut -d: -f1)
        PASSWORD=$(echo "$PAIR" | cut -d: -f2)

        # Skip if user does not exist
        if ! id "$USERNAME" > /dev/null 2>&1; then
            continue
        fi

        # Get the hash from /etc/shadow
        SHADOW_HASH=$(grep "^${USERNAME}:" /etc/shadow 2>/dev/null | cut -d: -f2)

        # Skip locked/disabled accounts
        if echo "$SHADOW_HASH" | grep -q '^[!*]'; then
            continue
        fi

        # Extract salt from the hash (format: $id$salt$hash)
        SALT=$(echo "$SHADOW_HASH" | grep -oP '^\$[^$]+\$[^$]+\$' 2>/dev/null)

        if [ -z "$SALT" ]; then
            # Try DES-style (first 2 chars are salt)
            SALT=$(echo "$SHADOW_HASH" | cut -c1-2)
            COMPUTED=$(perl -e "print crypt('$PASSWORD', '$SALT')" 2>/dev/null)
        else
            COMPUTED=$(python -c "import crypt; print crypt.crypt('$PASSWORD', '$SALT')" 2>/dev/null)
            if [ -z "$COMPUTED" ]; then
                COMPUTED=$(perl -e "print crypt('$PASSWORD', '$SALT')" 2>/dev/null)
            fi
        fi

        if [ "$COMPUTED" = "$SHADOW_HASH" ]; then
            echo "FAIL [PoC]: User '$USERNAME' still has the default weak password."
            WEAK_FOUND=1
        fi
    done

    if [ "$WEAK_FOUND" -eq 1 ]; then
        exit 1
    fi

    echo "PASS [PoC]: All default passwords have been changed (shadow check)."
fi

# Behavioral test: try SSH login with known weak credentials via sshpass if available
if ! pgrep -x sshd > /dev/null 2>&1; then
    /etc/init.d/ssh start > /dev/null 2>&1
    sleep 1
fi

if command -v sshpass > /dev/null 2>&1; then
    for PAIR in "msfadmin:msfadmin" "user:user" "root:root"; do
        B_USER=$(echo "$PAIR" | cut -d: -f1)
        B_PASS=$(echo "$PAIR" | cut -d: -f2)

        # Skip if user does not exist
        if ! id "$B_USER" > /dev/null 2>&1; then
            continue
        fi

        SSHPASS_OUT=$(sshpass -p "$B_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$B_USER"@127.0.0.1 echo LOGIN_OK 2>&1 || true)
        if echo "$SSHPASS_OUT" | grep -q "LOGIN_OK"; then
            echo "FAIL [PoC]: SSH login succeeded for '$B_USER' with default password (behavioral test)."
            exit 1
        fi
    done
    echo "PASS [PoC]: No default credential SSH logins succeeded (behavioral test)."
else
    echo "INFO [PoC]: sshpass not available; skipping SSH login behavioral test."
fi

###############################################################################
# Regression Check: Ensure sshd is running and functional
###############################################################################

# Check if sshd process is running
if pgrep -x sshd > /dev/null 2>&1; then
    echo "PASS [Regression]: sshd process is running."
elif /etc/init.d/ssh status 2>/dev/null | grep -qi "running"; then
    echo "PASS [Regression]: sshd service is running."
else
    # Try to start sshd and check again
    /etc/init.d/ssh start > /dev/null 2>&1
    sleep 1
    if pgrep -x sshd > /dev/null 2>&1; then
        echo "PASS [Regression]: sshd process started and is running."
    else
        echo "FAIL [Regression]: sshd is not running. Service may be broken."
        exit 1
    fi
fi

# Verify sshd is listening on port 22
if netstat -tlnp 2>/dev/null | grep -q ':22'; then
    echo "PASS [Regression]: sshd is listening on port 22."
else
    echo "FAIL [Regression]: sshd is not listening on port 22."
    exit 1
fi

echo "All checks passed."
exit 0
