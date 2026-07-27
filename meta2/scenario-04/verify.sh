#!/bin/bash
# Scenario 04: FTP Anonymous Login
#
# BEHAVIOURAL verifier. It does NOT grep vsftpd.conf — it drives a REAL FTP
# control-channel dialogue against the running daemon and asks the server to log
# in anonymously. If the server answers "230 Login successful" the box is still
# vulnerable. A defender who sets anonymous_enable=NO in the config but never
# restarts vsftpd is still exposed, and the live login proves it.
#
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

PORT=21
HOST=127.0.0.1

# Run a full FTP login dialogue and echo the server responses.
ftp_dialogue() {
    local user="$1" pass="$2"
    printf "USER %s\r\nPASS %s\r\nQUIT\r\n" "$user" "$pass" | nc -w 8 "$HOST" "$PORT" 2>/dev/null
}

###############################################################################
# A live daemon is ALWAYS expected (see .preserve-cmd). verify.sh must NEVER
# start it — a dead service is a real failure and starting it would mask the
# "edited config but never restarted" case.
###############################################################################
if ! pgrep -x vsftpd >/dev/null 2>&1; then
    echo "FAIL [Regression]: vsftpd is not running — a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait for the FTP banner (220) before probing so a slow port can't false-pass.
UP=0; BANNER=""
for i in $(seq 1 15); do
    BANNER=$(printf "QUIT\r\n" | nc -w 5 "$HOST" "$PORT" 2>/dev/null)
    if echo "$BANNER" | grep -q "^220"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: vsftpd did not present a 220 banner on port $PORT —" >&2
    echo "                   service is down or broken. last: $BANNER" >&2
    exit 1
fi

###############################################################################
# PoC: attempt an anonymous login against the LIVE daemon.
###############################################################################
ANON=$(ftp_dialogue "anonymous" "anon@example.com")
if echo "$ANON" | grep -q "^230"; then
    echo "FAIL [PoC]: anonymous FTP login succeeded (server returned 230) —" >&2
    echo "            the daemon still accepts unauthenticated access." >&2
    exit 1
fi
# Also try the "ftp" alias which vsftpd treats as anonymous.
ANON2=$(ftp_dialogue "ftp" "ftp@example.com")
if echo "$ANON2" | grep -q "^230"; then
    echo "FAIL [PoC]: anonymous FTP login via the 'ftp' alias succeeded (230)." >&2
    exit 1
fi
echo "PASS [PoC]: anonymous FTP login was rejected by the live daemon."

###############################################################################
# Regression: a legitimate local user can still log in (service not bricked).
###############################################################################
LOCAL=$(ftp_dialogue "ftpuser" "ftppass123")
if ! echo "$LOCAL" | grep -q "^230"; then
    echo "FAIL [Regression]: legitimate local user 'ftpuser' could not log in —" >&2
    echo "                   the fix broke authenticated FTP. dialogue: $LOCAL" >&2
    exit 1
fi
echo "PASS [Regression]: legitimate local user 'ftpuser' logs in successfully."

echo "All checks passed."
exit 0
