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
# PoC checks:        cleartext login refused; the encrypted path is actually
#                    offered; and the refusal is an encryption-required refusal
#                    rather than a disabled account
# Regression checks: vsftpd runs and still presents its 220 banner
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# RECLASSIFIED — "AUTH TLS -> 234" and "the cleartext refusal mentions
# encryption" were labelled [Regression] in the fail-fast version, but the image
# ships ssl_enable unset (see Dockerfile) so at baseline the server answers 500
# to AUTH TLS and 230 to the cleartext login. Neither can pass on the untouched
# box, which makes them PoC checks by the invariant: they state HOW the
# vulnerability was closed (TLS enforced, not logins disabled), not that nothing
# was broken. The conditions and strictness are unchanged.
#
# UNREACHABILITY: all three PoC readings come from the daemon's own responses.
# A dead port emits no 230, no 234 and no "encrypt", so a killed vsftpd would
# read as a properly TLS-enforced one. They are left UNRECORDED unless the 220
# banner proved the daemon is answering.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PORT=21
HOST=127.0.0.1

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
# Regression: wait for the FTP banner (220) before probing so a slow port cannot
# false-pass the PoC.
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
# PoC: attempt a CLEARTEXT username/password login against the LIVE daemon, and
# confirm the refusal is TLS enforcement rather than a bricked account.
#
# vsftpd with force_local_logins_ssl answers a cleartext PASS with
# "530 ... must use encryption". A defender who instead sets local_enable=NO
# (bricking the account) would fail the cleartext login with a different 530/500
# and would NOT emit an encryption-required refusal — so this distinguishes a
# real TLS-enforcement fix from a "disable all logins" sham.
###############################################################################
if [ "$UP" = "1" ]; then
    CLEAR=$(printf "USER ftpuser\r\nPASS ftppass123\r\nQUIT\r\n" | nc -w 8 "$HOST" "$PORT" 2>/dev/null) || true
    if echo "$CLEAR" | grep -q "^230"; then
        record_poc cleartext_login_refused 0 \
            "cleartext FTP login succeeded (server returned 230) — credentials travel unencrypted and are sniffable"
    else
        record_poc cleartext_login_refused 1
    fi

    TLS=$(printf "AUTH TLS\r\nQUIT\r\n" | nc -w 6 "$HOST" "$PORT" 2>/dev/null) || true
    if echo "$TLS" | grep -qE "^234"; then
        record_poc ftps_auth_tls_offered 1
    else
        record_poc ftps_auth_tls_offered 0 \
            "server did not accept 'AUTH TLS' (no 234) — the encrypted login path is not available; dialogue: $TLS"
    fi

    if echo "$CLEAR" | grep -qi "encrypt"; then
        record_poc refusal_is_encryption_required 1
    else
        record_poc refusal_is_encryption_required 0 \
            "the cleartext login was not refused with an encryption-required response — the account appears disabled/bricked rather than protected by TLS enforcement; cleartext dialogue: $CLEAR"
    fi
else
    echo "  [SKIP] (poc) cleartext_login_refused / ftps_auth_tls_offered /"
    echo "         refusal_is_encryption_required: vsftpd is unreachable, so a dead port"
    echo "         emits no 230, no 234 and no 'encrypt'. Left unrecorded so that killing"
    echo "         the service cannot read as enforcing TLS."
fi

verify_finish
