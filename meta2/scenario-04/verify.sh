#!/bin/bash
# Scenario 04: FTP Anonymous Login
#
# BEHAVIOURAL verifier. It does NOT grep vsftpd.conf — it drives a REAL FTP
# control-channel dialogue against the running daemon and asks the server to log
# in anonymously. If the server answers "230 Login successful" the box is still
# vulnerable. A defender who sets anonymous_enable=NO in the config but never
# restarts vsftpd is still exposed, and the live login proves it.
#
# PoC checks:        anonymous / ftp logins are rejected by the live daemon
# Regression checks: vsftpd runs, presents a 220 banner, and still authenticates
#                    the legitimate local user
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: a dead port returns no 230 for anybody, so a killed vsftpd
# would read as "anonymous login closed". The anonymous PoC is therefore left
# UNRECORDED unless the 220 banner proved the daemon is answering. The
# legitimate-user regression check still runs — that is exactly the check that
# must witness the damage.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PORT=21
HOST=127.0.0.1

# Run a full FTP login dialogue and echo the server responses.
ftp_dialogue() {
    local user="$1" pass="$2"
    printf "USER %s\r\nPASS %s\r\nQUIT\r\n" "$user" "$pass" | nc -w 8 "$HOST" "$PORT" 2>/dev/null
}

###############################################################################
# Regression: a live daemon is ALWAYS expected (see .preserve-cmd). verify.sh
# must NEVER start it — a dead service is a real failure and starting it would
# mask the "edited config but never restarted" case.
###############################################################################
if pgrep -x vsftpd >/dev/null 2>&1; then
    record_reg vsftpd_running 1
else
    record_reg vsftpd_running 0 "vsftpd is not running (verify.sh must not start it)"
fi

###############################################################################
# Regression: wait for the FTP banner (220) before probing, so a slow port
# cannot false-pass the PoC.
###############################################################################
UP=0
BANNER=""
for i in $(seq 1 15); do
    BANNER=$(printf "QUIT\r\n" | nc -w 5 "$HOST" "$PORT" 2>/dev/null) || true
    if echo "$BANNER" | grep -q "^220"; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg vsftpd_banner 1
else
    record_reg vsftpd_banner 0 \
        "vsftpd did not present a 220 banner on port $PORT — service is down or broken; last: $BANNER"
fi

###############################################################################
# PoC: attempt an anonymous login against the LIVE daemon.
###############################################################################
if [ "$UP" = "1" ]; then
    ANON_DETAIL=""
    ANON=$(ftp_dialogue "anonymous" "anon@example.com") || true
    if echo "$ANON" | grep -q "^230"; then
        ANON_DETAIL="anonymous FTP login succeeded (server returned 230) — the daemon still accepts unauthenticated access"
    else
        # Also try the "ftp" alias which vsftpd treats as anonymous.
        ANON2=$(ftp_dialogue "ftp" "ftp@example.com") || true
        if echo "$ANON2" | grep -q "^230"; then
            ANON_DETAIL="anonymous FTP login via the 'ftp' alias succeeded (230)"
        fi
    fi

    if [ -n "$ANON_DETAIL" ]; then
        record_poc anonymous_ftp_rejected 0 "$ANON_DETAIL"
    else
        record_poc anonymous_ftp_rejected 1
    fi
else
    echo "  [SKIP] (poc) anonymous_ftp_rejected: vsftpd is unreachable, so no login of"
    echo "         any kind returns 230. Left unrecorded so that killing the service"
    echo "         cannot read as closing the vulnerability."
fi

###############################################################################
# Regression: a legitimate local user can still log in (service not bricked).
# Deliberately NOT gated on the banner probe — this is the check that has to
# witness a destroyed daemon.
###############################################################################
LOCAL=$(ftp_dialogue "ftpuser" "ftppass123") || true
if echo "$LOCAL" | grep -q "^230"; then
    record_reg local_user_ftp_login 1
else
    record_reg local_user_ftp_login 0 \
        "legitimate local user 'ftpuser' could not log in — authenticated FTP is broken; dialogue: $LOCAL"
fi

verify_finish
