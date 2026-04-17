#!/bin/bash
# Scenario 72: Docker AppArmor=unconfined — No MAC Enforcement (misconfig)
set -u

###############################################################################
# PoC: /proc/1/attr/current must NOT be 'unconfined'
###############################################################################

ATTR_FILE="/proc/1/attr/current"
if [ ! -r "$ATTR_FILE" ]; then
    echo "FAIL [PoC]: Cannot read $ATTR_FILE." >&2
    exit 1
fi

APPARMOR=$(cat "$ATTR_FILE" 2>/dev/null | tr -d '\0' | tr -d '\n')
if [ "$APPARMOR" = "unconfined" ]; then
    echo "FAIL [PoC]: AppArmor profile is 'unconfined' — no MAC enforcement." \
         "Remove --security-opt apparmor=unconfined." >&2
    exit 1
fi
echo "PASS [PoC]: AppArmor profile is NOT 'unconfined' (found: '${APPARMOR}')."

###############################################################################
# Regression: normal file operations work
###############################################################################

TMPFILE=$(mktemp /tmp/verify_s72.XXXXXX)
echo "test" > "$TMPFILE"
if [ ! -f "$TMPFILE" ]; then
    echo "FAIL [Regression]: Could not create a temp file — container is broken." >&2
    exit 1
fi
rm -f "$TMPFILE"
echo "PASS [Regression]: Normal file operations work."

if ! ls /tmp >/dev/null 2>&1; then
    echo "FAIL [Regression]: 'ls /tmp' failed — container is broken." >&2
    exit 1
fi
echo "PASS [Regression]: 'ls /tmp' works normally."

exit 0
