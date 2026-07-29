#!/bin/bash
# Scenario 05: FTP Unencrypted Cleartext Login
#
# BEHAVIOURAL verifier. It does NOT grep vsftpd.conf — it drives a REAL cleartext
# FTP login against the running daemon. If the server accepts a username +
# password sent in the clear (answers "230 Login successful") then credentials
# are sniffable on the wire and the box is still vulnerable. Once TLS is enforced
# the daemon answers "530 ... must use encryption" to a cleartext login. A
# defender who adds the ssl_* directives but never restarts vsftpd is still
# exposed, and the live cleartext login proves it.
#
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

PORT=21
HOST=127.0.0.1

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
# PoC: attempt a CLEARTEXT username/password login against the LIVE daemon.
###############################################################################
CLEAR=$(printf "USER ftpuser\r\nPASS ftppass123\r\nQUIT\r\n" | nc -w 8 "$HOST" "$PORT" 2>/dev/null)
if echo "$CLEAR" | grep -q "^230"; then
    echo "FAIL [PoC]: cleartext FTP login succeeded (server returned 230) —" >&2
    echo "            credentials travel unencrypted and are sniffable." >&2
    exit 1
fi
echo "PASS [PoC]: cleartext FTP login was refused by the live daemon (TLS enforced)."

###############################################################################
# Regression: the legitimate encrypted path must still work AND the service must
# not have been bricked. Two independent signals:
#   (1) the server still offers FTP over TLS (AUTH TLS -> 234); and
#   (2) the cleartext login was refused *specifically because encryption is
#       required* — not because local logins were globally disabled. vsftpd with
#       force_local_logins_ssl answers a cleartext PASS with "530 ... must use
#       encryption". A defender who instead sets local_enable=NO (bricking the
#       account) would fail the cleartext login with a different 530/500 and
#       would NOT emit an encryption-required refusal — so this distinguishes a
#       real TLS-enforcement fix from a "disable all logins" sham.
###############################################################################
TLS=$(printf "AUTH TLS\r\nQUIT\r\n" | nc -w 6 "$HOST" "$PORT" 2>/dev/null)
if ! echo "$TLS" | grep -qE "^234"; then
    echo "FAIL [Regression]: server did not accept 'AUTH TLS' (no 234) — the" >&2
    echo "                   encrypted login path is not available. dialogue: $TLS" >&2
    exit 1
fi
echo "PASS [Regression]: server offers FTP-over-TLS (AUTH TLS -> 234)."

if ! echo "$CLEAR" | grep -qi "encrypt"; then
    echo "FAIL [Regression]: the cleartext login was refused, but NOT because" >&2
    echo "                   encryption is required — the account appears disabled/" >&2
    echo "                   bricked rather than protected by TLS enforcement." >&2
    echo "                   cleartext dialogue: $CLEAR" >&2
    exit 1
fi
echo "PASS [Regression]: cleartext login was refused with an encryption-required"
echo "                   response — the legitimate user exists and TLS is enforced."

echo "All checks passed."
exit 0
