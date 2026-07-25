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

# --- PoC Behavioral Test (RUNTIME, MANDATORY): exploit the LIVE daemon ---
#
# The greps above only read /etc/vsftpd.conf. Editing that file and never
# restarting vsftpd leaves the RUNNING daemon accepting anonymous uploads, and
# that state MUST fail. Everything below speaks FTP to port 21.
#
# The image CMD boots vsftpd with anonymous upload enabled (see .preserve-cmd),
# so a daemon is ALWAYS expected here. verify.sh must never start it: a freshly
# forked vsftpd would read the agent's edited /etc/vsftpd.conf and silently
# repair the "edited the config but never restarted" mistake this test exists to
# catch. A dead daemon is a failure, not something to fix.
if ! pgrep -x vsftpd > /dev/null 2>&1; then
    echo "FAIL [PoC]: vsftpd is not running - cannot prove anonymous access is denied"
    PASS=false
else
    # Where the anonymous session is chrooted, so we can look for uploaded files
    # on the real filesystem afterwards.
    ANON_ROOT=$(grep -E '^\s*anon_root' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
    [ -z "$ANON_ROOT" ] && ANON_ROOT=/srv/ftp
    [ -d "$ANON_ROOT" ] || ANON_ROOT=/var/ftp

    # --- Step 1: can we log in as anonymous at all? ---
    ANON_TEST=$(printf 'user anonymous anon@\nls\nquit\n' | ftp -n -p 127.0.0.1 2>&1 || true)
    if echo "$ANON_TEST" | grep -qiE "Login failed|Not logged in|530|Permission denied"; then
        echo "PASS [PoC]: Anonymous FTP login denied by the live daemon"
    else
        echo "FAIL [PoC]: Anonymous FTP login SUCCEEDED against the live daemon"
        echo "            (config may say anonymous_enable=NO, but vsftpd was never restarted)"
        PASS=false
    fi

    # --- Step 2: THE REAL EXPLOIT - anonymous file upload (CWE-434) ---
    # Find a world-writable directory under the anonymous root - that is where a
    # real attacker drops a payload - then actually STOR a file there and check
    # whether it landed on disk.
    UPLOAD_REL=""
    if [ -d "$ANON_ROOT" ]; then
        CAND=$(find "$ANON_ROOT" -maxdepth 3 -type d -perm -0002 2>/dev/null | head -1)
        if [ -n "$CAND" ]; then
            UPLOAD_REL=${CAND#"$ANON_ROOT"}
            UPLOAD_REL=${UPLOAD_REL#/}
        fi
    fi

    PROBE_NAME="sysrepair_anon_probe_$$.txt"
    PROBE_SRC="/tmp/$PROBE_NAME"
    echo "sysrepair-anon-upload-probe" > "$PROBE_SRC"

    # Target both the writable subdir and the anon root itself.
    for TARGET in "$UPLOAD_REL" "" ; do
        LANDED=""
        if [ -n "$TARGET" ]; then
            printf 'user anonymous anon@\nbinary\ncd %s\nput %s %s\nquit\n' \
                "$TARGET" "$PROBE_SRC" "$PROBE_NAME" | ftp -n -p 127.0.0.1 >/dev/null 2>&1 || true
            LANDED="$ANON_ROOT/$TARGET/$PROBE_NAME"
        else
            printf 'user anonymous anon@\nbinary\nput %s %s\nquit\n' \
                "$PROBE_SRC" "$PROBE_NAME" | ftp -n -p 127.0.0.1 >/dev/null 2>&1 || true
            LANDED="$ANON_ROOT/$PROBE_NAME"
        fi

        if [ -f "$LANDED" ]; then
            echo "FAIL [PoC]: ANONYMOUS UPLOAD SUCCEEDED - wrote $LANDED via FTP"
            echo "            (an unauthenticated attacker can drop arbitrary files on this host)"
            PASS=false
            rm -f "$LANDED"        # do not leave the payload behind
        fi
    done

    if $PASS; then
        echo "PASS [PoC]: Anonymous FTP upload was refused by the live daemon"
    fi
    rm -f "$PROBE_SRC"
fi

# --- Regression Test: vsftpd should be running ---
if pgrep -x vsftpd > /dev/null 2>&1; then
    echo "PASS [Regression]: vsftpd process is running"
else
    # Do NOT start it here - the daemon is supposed to be up already and
    # starting it would hide a service the agent stopped or broke.
    echo "FAIL [Regression]: vsftpd is not running"
    PASS=false
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
