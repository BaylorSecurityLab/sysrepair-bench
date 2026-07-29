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
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.
set -u
HOST=127.0.0.1
PORT=5432

if ! pgrep -x postgres >/dev/null 2>&1; then
    echo "FAIL [Regression]: PostgreSQL is not running -- a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait (bounded) for the port to accept connections.
UP=0
for i in $(seq 1 20); do
    if netstat -tln 2>/dev/null | grep -q ":$PORT " || ss -tln 2>/dev/null | grep -q ":$PORT "; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != 1 ]; then
    echo "FAIL [Regression]: PostgreSQL is not listening on port $PORT -- service down/broken." >&2
    exit 1
fi

OV=$(openssl version 2>/dev/null | awk '{print $2}')
echo "INFO: system OpenSSL version: ${OV:-unknown} (CVE-2014-0224 unpatched on EOL Hardy)."

# PoC: the PostgreSQL SSLRequest handshake. 'S' => the live server offers TLS
# over the vulnerable OpenSSL; 'N' => SSL disabled.
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
)

if [ "$SSL_REPLY" = "S" ]; then
    echo "FAIL [PoC]: the live PostgreSQL server offers SSL/TLS (SSLRequest -> 'S')" >&2
    echo "            over CVE-2014-0224-vulnerable OpenSSL -- MitM/CCS-injection exposure." >&2
    exit 1
elif [ "$SSL_REPLY" = "N" ]; then
    echo "PASS [PoC]: the live server declines SSL (SSLRequest -> 'N')."
else
    echo "FAIL [PoC]: could not complete the SSLRequest handshake (reply='$SSL_REPLY')." >&2
    exit 1
fi

# Regression: PostgreSQL still answers queries.
PGRESULT=$(su - postgres -c "psql -d testdb -tAc 'SELECT name FROM test_data LIMIT 1;'" 2>/dev/null | tr -d '[:space:]')
if [ "$PGRESULT" = "test_entry" ]; then
    echo "PASS [Regression]: PostgreSQL still answers queries (test_entry)."
else
    echo "FAIL [Regression]: PostgreSQL did not return the expected row -- service broken." >&2
    echo "                   got: '${PGRESULT}'" >&2
    exit 1
fi

echo "All checks passed."
exit 0
