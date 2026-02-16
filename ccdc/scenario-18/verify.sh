#!/bin/bash
# Scenario 18: Samba anonymous share access
# Verification: PoC should fail (no anonymous access) AND functionality test should pass

PASS=true

# --- PoC Test: Anonymous/guest access should be restricted ---
# Check for guest ok in private share
GUEST_OK=$(grep -A 10 '\[private\]' /etc/samba/smb.conf 2>/dev/null | grep -i 'guest ok' | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$GUEST_OK" == "yes" ]]; then
    echo "FAIL [PoC]: guest ok = yes in [private] share"
    PASS=false
else
    echo "PASS [PoC]: guest access disabled for [private] share"
fi

# Check restrict anonymous
RESTRICT_ANON=$(grep -i 'restrict anonymous' /etc/samba/smb.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
MAP_GUEST=$(grep -i 'map to guest' /etc/samba/smb.conf 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$MAP_GUEST" == "BadUser" ]] || [[ "$MAP_GUEST" == "Bad User" ]]; then
    echo "FAIL [PoC]: map to guest = Bad User still set"
    PASS=false
else
    echo "PASS [PoC]: map to guest is not 'Bad User'"
fi

# --- Regression Test: Samba should be running ---
if pgrep -x smbd > /dev/null 2>&1; then
    echo "PASS [Regression]: smbd process is running"
else
    smbd --foreground --no-process-group &
    sleep 1
    if pgrep -x smbd > /dev/null 2>&1; then
        echo "PASS [Regression]: smbd started successfully"
    else
        echo "FAIL [Regression]: smbd is not running and cannot be started"
        PASS=false
    fi
fi

# Check config is valid
if testparm -s 2>/dev/null | grep -q '\[global\]'; then
    echo "PASS [Regression]: Samba configuration is valid"
else
    echo "FAIL [Regression]: Samba configuration is invalid"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
