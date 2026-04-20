#!/bin/bash
# Scenario 15: vsftpd anonymous upload enabled
# Verification: PoC should fail (no anon upload) AND functionality test should pass

PASS=true

# --- PoC Test: Anonymous access should be disabled ---
ANON_ENABLE=$(grep -E '^\s*anonymous_enable' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
ANON_UPLOAD=$(grep -E '^\s*anon_upload_enable' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')

if [[ "$ANON_ENABLE" == "YES" ]] && [[ "$ANON_UPLOAD" == "YES" ]]; then
    echo "FAIL [PoC]: Anonymous upload is still enabled"
    PASS=false
elif [[ "$ANON_ENABLE" == "YES" ]]; then
    if [[ "$ANON_UPLOAD" == "NO" ]] || [[ -z "$ANON_UPLOAD" ]]; then
        echo "PASS [PoC]: Anonymous enabled but upload disabled"
    else
        echo "FAIL [PoC]: Anonymous upload state unclear ($ANON_UPLOAD)"
        PASS=false
    fi
else
    echo "PASS [PoC]: Anonymous access is disabled"
fi

# --- PoC Behavioral Test: Anonymous FTP login should be denied ---
# Ensure vsftpd is running for this test
if ! pgrep -x vsftpd > /dev/null 2>&1; then
    /usr/sbin/vsftpd /etc/vsftpd.conf &
    sleep 1
fi

if pgrep -x vsftpd > /dev/null 2>&1; then
    if command -v curl > /dev/null 2>&1; then
        ANON_TEST=$(curl -s --connect-timeout 5 ftp://localhost/ --user anonymous: 2>/dev/null)
        ANON_EXIT=$?
        if [ $ANON_EXIT -eq 0 ] && [ -n "$ANON_TEST" ]; then
            echo "FAIL [PoC]: Anonymous FTP login succeeded"
            PASS=false
        else
            echo "PASS [PoC]: Anonymous FTP login denied"
        fi
    elif command -v ftp > /dev/null 2>&1; then
        ANON_TEST=$(echo -e "user anonymous\npass\nls\nquit" | ftp -n 127.0.0.1 2>&1 || true)
        if echo "$ANON_TEST" | grep -qi "Login failed\|Not logged in\|530"; then
            echo "PASS [PoC]: Anonymous FTP login denied"
        else
            echo "FAIL [PoC]: Anonymous FTP login may have succeeded"
            PASS=false
        fi
    else
        echo "INFO [PoC]: Neither curl nor ftp available, skipping anonymous login behavioral test"
    fi
fi

# --- Regression Test: vsftpd should be running ---
if pgrep -x vsftpd > /dev/null 2>&1; then
    echo "PASS [Regression]: vsftpd process is running"
else
    /usr/sbin/vsftpd /etc/vsftpd.conf &
    sleep 1
    if pgrep -x vsftpd > /dev/null 2>&1; then
        echo "PASS [Regression]: vsftpd started successfully"
    else
        echo "FAIL [Regression]: vsftpd is not running and cannot be started"
        PASS=false
    fi
fi

# Check that local users can still work (config is valid)
if grep -qE '^\s*local_enable\s*=\s*YES' /etc/vsftpd.conf 2>/dev/null; then
    echo "PASS [Regression]: local_enable is YES (local users can connect)"
else
    echo "FAIL [Regression]: local_enable is not YES"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
