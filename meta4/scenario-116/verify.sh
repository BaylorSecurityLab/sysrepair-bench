#!/bin/bash
# Scenario 116: Rsync Daemon — No Authentication / No ACL (misconfig)
set -u

###############################################################################
# Wait for rsync daemon to start
###############################################################################

for i in $(seq 1 10); do
    if rsync rsync://localhost/ >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

###############################################################################
# PoC: unauthenticated access must be denied
###############################################################################

# Try to list the module without credentials
OUTPUT=$(rsync rsync://localhost/data/etc/passwd 2>&1 || true)

if echo "$OUTPUT" | grep -qi "auth required\|password\|permission denied\|error.*auth\|@ERROR"; then
    echo "PASS [PoC]: Unauthenticated rsync access is denied."
elif echo "$OUTPUT" | grep -q "root:"; then
    echo "FAIL [PoC]: /etc/passwd content returned without credentials — no auth on rsync." >&2
    exit 1
else
    # Could be connection refused if daemon not running, or auth error
    if echo "$OUTPUT" | grep -qi "connection refused\|unable to connect\|no route"; then
        echo "FAIL [PoC]: rsync daemon is not running." >&2
        exit 1
    fi
    echo "PASS [PoC]: Unauthenticated access did not return sensitive content."
fi

###############################################################################
# PoC 2: check rsyncd.conf requires auth users
###############################################################################

if grep -q "auth users" /etc/rsyncd.conf 2>/dev/null; then
    echo "PASS [PoC]: rsyncd.conf contains 'auth users' — authentication configured."
else
    echo "FAIL [PoC]: rsyncd.conf has no 'auth users' — module is open." >&2
    exit 1
fi

if grep -q "secrets file" /etc/rsyncd.conf 2>/dev/null; then
    echo "PASS [PoC]: rsyncd.conf references a secrets file."
else
    echo "FAIL [PoC]: rsyncd.conf has no 'secrets file'." >&2
    exit 1
fi

###############################################################################
# Regression: rsync daemon must be reachable and authenticated access works
###############################################################################

SECRETS_FILE=$(grep "secrets file" /etc/rsyncd.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || true)
AUTH_USER=$(grep "auth users" /etc/rsyncd.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' | cut -d',' -f1 || true)

if [ -n "$SECRETS_FILE" ] && [ -f "$SECRETS_FILE" ] && [ -n "$AUTH_USER" ]; then
    # Create a temp password file from the secrets file for this user
    PASS=$(grep "^${AUTH_USER}:" "$SECRETS_FILE" 2>/dev/null | cut -d: -f2 || true)
    if [ -n "$PASS" ]; then
        TMPPASS=$(mktemp)
        echo "$PASS" > "$TMPPASS"
        chmod 600 "$TMPPASS"
        LIST=$(rsync --password-file="$TMPPASS" "rsync://${AUTH_USER}@localhost/data/" 2>&1 || true)
        rm -f "$TMPPASS"
        if echo "$LIST" | grep -qi "error\|failed\|denied"; then
            echo "FAIL [Regression]: Authenticated rsync failed: $LIST" >&2
            exit 1
        else
            echo "PASS [Regression]: Authenticated rsync access works."
        fi
    else
        echo "INFO [Regression]: Could not extract password for user '$AUTH_USER' — skipping auth test."
    fi
else
    # At minimum, daemon must be listening
    if rsync rsync://localhost/ >/dev/null 2>&1 || rsync rsync://localhost/ 2>&1 | grep -q "@ERROR\|auth"; then
        echo "PASS [Regression]: rsync daemon is running and responding."
    else
        echo "FAIL [Regression]: rsync daemon is not reachable." >&2
        exit 1
    fi
fi

exit 0
