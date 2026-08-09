#!/bin/bash
# Scenario 23: PostgreSQL SSLv3 / POODLE (CVE-2014-3566)
#
# BEHAVIOURAL verifier. It does NOT grep postgresql.conf or the OpenSSL version.
# It speaks the PostgreSQL SSLRequest handshake to the LIVE postmaster and then
# forces an SSLv3-only TLS handshake. If the server completes an SSLv3 handshake
# it is exposed to POODLE; if it answers the SSLRequest with 'N' (SSL disabled)
# or refuses SSLv3 while still speaking TLSv1, it is remediated.
#
# Truth table:
#   ssl on, OpenSSL 0.9.8g, postmaster running   -> SSLv3 handshake OK -> FAIL
#   ssl = off + postmaster restarted             -> SSLRequest 'N'     -> PASS
#   ssl = off in conf but NOT restarted          -> live server 'S'+SSLv3 -> FAIL
#   nothing done                                 -> SSLv3 handshake OK -> FAIL
#
# PoC checks:        the live postmaster is not exploitable via SSLv3/POODLE
#                    (RC 0 = SSL off, or SSLv3 refused with TLSv1 still ok)
# Regression checks: postgres runs and the postmaster answers the SSLRequest
#                    handshake on 5432 (not PG_DOWN / ambiguous)
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: the safe/vulnerable verdict (RC 0/1) is only produced when the
# postmaster answered. A dead postmaster reports PG_DOWN (RC 3), in which case
# the PoC is left UNRECORDED and the failure is recorded on the regression side —
# so killing the daemon cannot read as disabling SSL.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

POC=/tmp/pg_poodle.$$.py
trap 'rm -f "$POC"' EXIT

###############################################################################
# Regression: a live postmaster is always expected (see .preserve-cmd). Never
# start it.
###############################################################################
if pgrep -x postgres >/dev/null 2>&1; then
    record_reg postgres_running 1
else
    record_reg postgres_running 0 "PostgreSQL postmaster is not running (verify.sh must not start it)"
fi

cat > "$POC" <<'PY'
import socket, struct, time, select, sys
from OpenSSL import SSL

HOST, PORT = "127.0.0.1", 5432
SSLREQUEST = struct.pack("!ii", 8, 80877103)   # PostgreSQL SSLRequest code

def ssl_request():
    """Return the postmaster's SSLRequest reply byte ('S'/'N'), plus the socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6); s.connect((HOST, PORT))
    s.sendall(SSLREQUEST)
    r = s.recv(1)
    return r, s

def try_handshake(method):
    r, s = ssl_request()
    if r != "S":
        return r, None
    s.setblocking(1)
    ctx = SSL.Context(method)
    conn = SSL.Connection(ctx, s); conn.set_connect_state()
    dl = time.time() + 8
    while True:
        try:
            conn.do_handshake(); return "S", "ok"
        except SSL.WantReadError:
            if time.time() > dl:
                return "S", "timeout"
            select.select([s], [], [], 2)
        except Exception, e:
            return "S", "failed"

# Bounded wait for the postmaster to answer the SSLRequest at all.
reply = None
for _ in range(20):
    try:
        reply, _ = ssl_request()
        if reply in ("S", "N"):
            break
    except Exception:
        reply = None
    time.sleep(1)
if reply not in ("S", "N"):
    print("PG_DOWN: postmaster did not answer SSLRequest on 5432")
    sys.exit(3)

if reply == "N":
    print("REMEDIATED: SSL disabled (SSLRequest -> 'N'); postmaster is alive.")
    sys.exit(0)

# SSL offered -> try to complete an SSLv3-only handshake (POODLE).
_, res = try_handshake(SSL.SSLv3_METHOD)
if res == "ok":
    print("VULNERABLE: PostgreSQL completed an SSLv3 handshake (POODLE / CVE-2014-3566).")
    sys.exit(1)

# SSLv3 refused but SSL still on -> confirm TLSv1 still works (regression).
_, res_tls = try_handshake(SSL.TLSv1_METHOD)
if res_tls == "ok":
    print("REMEDIATED: SSLv3 refused; TLSv1 still negotiates.")
    sys.exit(0)

print("AMBIGUOUS: SSL offered but neither SSLv3 nor TLSv1 completed (res=%s)" % res)
sys.exit(4)
PY

OUT=$(python "$POC" 2>&1)
RC=$?
echo "$OUT"

case "$RC" in
    0)
        record_poc sslv3_poodle_closed 1
        record_reg postmaster_answers_sslrequest 1
        ;;
    1)
        record_poc sslv3_poodle_closed 0 \
            "PostgreSQL negotiated SSLv3 against the live postmaster (POODLE / CVE-2014-3566)"
        record_reg postmaster_answers_sslrequest 1
        ;;
    3)
        echo "  [SKIP] (poc) sslv3_poodle_closed: the postmaster did not answer the"
        echo "         SSLRequest (PG_DOWN), so SSLv3 exploitability cannot be judged."
        echo "         Left unrecorded so that killing the daemon cannot read as disabling SSL."
        record_reg postmaster_answers_sslrequest 0 "postmaster did not answer SSLRequest on 5432 (rc=$RC): $OUT"
        ;;
    *)
        echo "  [SKIP] (poc) sslv3_poodle_closed: the SSL probe was ambiguous (rc=$RC),"
        echo "         so the SSLv3 verdict is unreliable. Left unrecorded."
        record_reg postmaster_answers_sslrequest 0 "SSL probe did not complete cleanly (rc=$RC): $OUT"
        ;;
esac

verify_finish
