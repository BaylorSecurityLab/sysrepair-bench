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
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u
POC=/tmp/pg_poodle.$$.py
trap 'rm -f "$POC"' EXIT

###############################################################################
# A live postmaster is always expected (see .preserve-cmd). Never start it.
###############################################################################
if ! pgrep -x postgres >/dev/null 2>&1; then
    echo "FAIL [Regression]: PostgreSQL postmaster is not running — a dead service" >&2
    echo "                   is a failure (verify.sh must not start it)." >&2
    exit 1
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
        echo "PASS [PoC]: PostgreSQL is not exploitable via SSLv3/POODLE."
        echo "PASS [Regression]: PostgreSQL postmaster answers on port 5432."
        echo "All checks passed."
        exit 0
        ;;
    1)
        echo "FAIL [PoC]: PostgreSQL negotiated SSLv3 against the live postmaster." >&2
        exit 1
        ;;
    *)
        echo "FAIL [Regression]: could not exercise the live PostgreSQL SSL service" >&2
        echo "                   (rc=$RC). A broken/dead service is a failure." >&2
        exit 1
        ;;
esac
