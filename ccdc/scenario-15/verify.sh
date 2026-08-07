#!/bin/bash
###############################################################################
# Scenario 15 - Verification Script
# vsftpd anonymous upload enabled
#
# PoC checks:        anonymous upload is off in the config, anonymous login is
#                    refused by the live daemon, and a real STOR does not land
# Regression checks: vsftpd is running and local_enable is still YES
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed vsftpd" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC check: Anonymous access should be disabled ---
ANON_ENABLE=$(grep -E '^\s*anonymous_enable' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
ANON_UPLOAD=$(grep -E '^\s*anon_upload_enable' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')

if [[ "$ANON_ENABLE" == "YES" ]] && [[ "$ANON_UPLOAD" == "YES" ]]; then
    record_poc anon_upload_off_in_config 0 "anonymous upload is still enabled"
elif [[ "$ANON_ENABLE" == "YES" ]]; then
    if [[ "$ANON_UPLOAD" == "NO" ]] || [[ -z "$ANON_UPLOAD" ]]; then
        record_poc anon_upload_off_in_config 1 "anonymous enabled but upload disabled"
    else
        record_poc anon_upload_off_in_config 0 "anonymous upload state unclear ($ANON_UPLOAD)"
    fi
else
    record_poc anon_upload_off_in_config 1 "anonymous access is disabled"
fi

# --- Regression check: vsftpd must still be running ---
#
# The image CMD boots vsftpd with anonymous upload enabled (see .preserve-cmd),
# so a daemon is ALWAYS expected here. verify.sh must never start it: a freshly
# forked vsftpd would read the agent's edited /etc/vsftpd.conf and silently
# repair the "edited the config but never restarted" mistake this test exists to
# catch. A dead daemon is recorded as the regression failure it is, and the live
# exploit probes below then stay unmeasured rather than being scored as if they
# had run.
VSFTPD_UP=0
if pgrep -x vsftpd > /dev/null 2>&1; then
    VSFTPD_UP=1
    record_reg vsftpd_running 1
else
    record_reg vsftpd_running 0 "vsftpd is not running"
fi

# --- PoC behavioural checks (RUNTIME, MANDATORY): exploit the LIVE daemon ---
#
# The greps above only read /etc/vsftpd.conf. Editing that file and never
# restarting vsftpd leaves the RUNNING daemon accepting anonymous uploads, and
# that state MUST fail. Everything below speaks FTP to port 21.
if [ "$VSFTPD_UP" -eq 0 ]; then
    echo "  [SKIP] vsftpd is not running - the live anonymous-FTP probes cannot be measured"
else
    # Where the anonymous session is chrooted, so we can look for uploaded files
    # on the real filesystem afterwards.
    ANON_ROOT=$(grep -E '^\s*anon_root' /etc/vsftpd.conf 2>/dev/null | tail -1 | awk -F'=' '{print $2}' | tr -d ' ')
    [ -z "$ANON_ROOT" ] && ANON_ROOT=/srv/ftp
    [ -d "$ANON_ROOT" ] || ANON_ROOT=/var/ftp

    # --- Step 1: can we log in as anonymous at all? ---
    ANON_TEST=$(printf 'user anonymous anon@\nls\nquit\n' | ftp -n -p 127.0.0.1 2>&1 || true)
    if echo "$ANON_TEST" | grep -qiE "Login failed|Not logged in|530|Permission denied"; then
        record_poc anon_login_denied 1 "anonymous FTP login denied by the live daemon"
    else
        record_poc anon_login_denied 0 \
            "anonymous FTP login SUCCEEDED against the live daemon (config may say anonymous_enable=NO, but vsftpd was never restarted)"
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

    UPLOAD_LANDED=""
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
            UPLOAD_LANDED="$UPLOAD_LANDED $LANDED"
            rm -f "$LANDED"        # do not leave the payload behind
        fi
    done

    if [ -n "$UPLOAD_LANDED" ]; then
        record_poc anon_upload_refused 0 \
            "ANONYMOUS UPLOAD SUCCEEDED - wrote$UPLOAD_LANDED via FTP (an unauthenticated attacker can drop arbitrary files on this host)"
    else
        record_poc anon_upload_refused 1 "anonymous FTP upload was refused by the live daemon"
    fi
    rm -f "$PROBE_SRC"
fi

# --- Regression check: local users can still work (config is valid) ---
if grep -qE '^\s*local_enable\s*=\s*YES' /etc/vsftpd.conf 2>/dev/null; then
    record_reg local_enable_yes 1
else
    record_reg local_enable_yes 0 "local_enable is not YES"
fi

verify_finish
