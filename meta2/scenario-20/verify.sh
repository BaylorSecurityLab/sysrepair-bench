#!/bin/bash
# Verify remediation of Samba MS-RPC Shell Command Execution CVE-2007-2447 (scenario-20)

PASS=0
FAIL=1

##############################################
# PoC Check: 'username map script' must NOT be in smb.conf
##############################################

# Check if the vulnerable directive exists in smb.conf
if grep -qi "username map script" /etc/samba/smb.conf 2>/dev/null; then
    echo "FAIL: 'username map script' is still present in /etc/samba/smb.conf"
    exit $FAIL
fi

# Also check any included configuration files
SMB_INCLUDES=$(grep -i "^include" /etc/samba/smb.conf 2>/dev/null | awk '{print $3}')
for INCFILE in $SMB_INCLUDES; do
    if [ -f "$INCFILE" ] && grep -qi "username map script" "$INCFILE" 2>/dev/null; then
        echo "FAIL: 'username map script' found in included config $INCFILE"
        exit $FAIL
    fi
done

echo "PASS: 'username map script' directive has been removed (config check)"

# Behavioral test: attempt to exploit metacharacter injection via smbclient
# Ensure Samba is running
if ! pidof smbd > /dev/null 2>&1; then
    /etc/init.d/samba start > /dev/null 2>&1 || smbd -D > /dev/null 2>&1
    sleep 2
fi

if command -v smbclient > /dev/null 2>&1; then
    # Create a marker file that would be created if command injection succeeds
    MARKER="/tmp/.samba_exploit_test_$$"
    rm -f "$MARKER"

    # Attempt metacharacter injection in username — if vulnerable, the backtick
    # command would execute and create the marker file
    smbclient //127.0.0.1/tmp -U "/=\`touch ${MARKER}\`" -N 2>/dev/null || true

    if [ -f "$MARKER" ]; then
        rm -f "$MARKER"
        echo "FAIL: Metacharacter injection via smbclient username succeeded (behavioral test)"
        exit $FAIL
    fi
    rm -f "$MARKER"
    echo "PASS: Metacharacter injection via smbclient username did not execute (behavioral test)"
else
    echo "INFO: smbclient not available; skipping metacharacter injection behavioral test"
fi

##############################################
# Regression Check: Samba must still be running and shares accessible
##############################################

# Check that smbd is running
if ! pidof smbd > /dev/null 2>&1; then
    echo "FAIL: smbd is not running"
    exit $FAIL
fi

# Check that port 445 is listening
if ! netstat -tlnp 2>/dev/null | grep -q ':445 '; then
    echo "FAIL: Samba is not listening on port 445"
    exit $FAIL
fi

# Try to list shares
SHARES=$(smbclient -L 127.0.0.1 -N 2>/dev/null)
if [ $? -ne 0 ] && [ -z "$SHARES" ]; then
    echo "FAIL: Cannot list Samba shares"
    exit $FAIL
fi

# Check that the shared directory is accessible
if echo "$SHARES" | grep -qi "shared"; then
    echo "PASS: Samba share 'shared' is accessible"
else
    echo "FAIL: Samba share 'shared' is not listed"
    exit $FAIL
fi

echo "PASS: Samba is functional with shares accessible"
exit $PASS
