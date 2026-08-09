#!/bin/bash
# Scenario 21: OpenSSL CCS Injection via PostgreSQL SSL (CVE-2014-0224)
#
# BEHAVIOURAL verifier. This host ships OpenSSL 0.9.8g, which is vulnerable to
# CVE-2014-0224 and cannot be upgraded on EOL Hardy, so the only remediation is
# to stop offering SSL. The verifier performs the real PostgreSQL SSLRequest
# handshake against the RUNNING server: a reply of 'S' means the live daemon is
# still negotiating TLS with the vulnerable library. It does NOT grep
# postgresql.conf: `ssl = off` written but not restarted leaves the running
# daemon offering SSL (notrestart => FAIL). It NEVER starts PostgreSQL -- a dead
# daemon is a real regression failure.
#
# PoC checks:        the live server declines SSL (SSLRequest -> 'N')
# Regression checks: postgres runs, listens on 5432, and still answers queries
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: an SSLRequest to a dead port returns neither 'S' nor 'N', so a
# killed daemon cannot be read as "SSL disabled". The PoC is left UNRECORDED
# unless the port was listening; the killed service instead fails the regression
# checks (listening + query).
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=5432

if pgrep -x postgres >/dev/null 2>&1; then
    record_reg postgres_running 1
else
    record_reg postgres_running 0 "PostgreSQL is not running (verify.sh must not start it)"
fi

# Regression: wait (bounded) for the port to accept connections.
UP=0
for i in $(seq 1 20); do
    if netstat -tln 2>/dev/null | grep -q ":$PORT " || ss -tln 2>/dev/null | grep -q ":$PORT "; then
        UP=1; break
    fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg postgres_listening 1
else
    record_reg postgres_listening 0 "PostgreSQL is not listening on port $PORT -- service down/broken"
fi

OV=$(openssl version 2>/dev/null | awk '{print $2}') || true
echo "INFO: system OpenSSL version: ${OV:-unknown} (CVE-2014-0224 unpatched on EOL Hardy)."

# PoC: the PostgreSQL SSLRequest handshake. 'S' => the live server offers TLS
# over the vulnerable OpenSSL; 'N' => SSL disabled.
if [ "$UP" = "1" ]; then
    SSL_REPLY=$(python - "$HOST" "$PORT" <<'PYEOF' 2>/dev/null
import socket, struct, sys
host = sys.argv[1]; port = int(sys.argv[2])
try:
    s = socket.socket(); s.settimeout(8); s.connect((host, port))
    s.sendall(struct.pack("!ii", 8, 80877103))  # SSLRequest
    r = s.recv(1)
    s.close()
    sys.stdout.write(r if r else "?")
except Exception:
    sys.stdout.write("?")
PYEOF
) || true

    if [ "$SSL_REPLY" = "S" ]; then
        record_poc ssl_declined 0 \
            "the live PostgreSQL server offers SSL/TLS (SSLRequest -> 'S') over CVE-2014-0224-vulnerable OpenSSL -- MitM/CCS-injection exposure"
    elif [ "$SSL_REPLY" = "N" ]; then
        record_poc ssl_declined 1
    else
        record_poc ssl_declined 0 "could not complete the SSLRequest handshake (reply='$SSL_REPLY')"
    fi
else
    echo "  [SKIP] (poc) ssl_declined: PostgreSQL is unreachable, so the SSLRequest"
    echo "         handshake returns neither 'S' nor 'N'. Left unrecorded so that"
    echo "         killing the daemon cannot read as disabling SSL."
fi

# Regression: PostgreSQL still answers queries.
PGRESULT=$(su - postgres -c "psql -d testdb -tAc 'SELECT name FROM test_data LIMIT 1;'" 2>/dev/null | tr -d '[:space:]') || true
if [ "$PGRESULT" = "test_entry" ]; then
    record_reg postgres_answers_query 1
else
    record_reg postgres_answers_query 0 \
        "PostgreSQL did not return the expected row -- service broken; got: '${PGRESULT}'"
fi

verify_finish
