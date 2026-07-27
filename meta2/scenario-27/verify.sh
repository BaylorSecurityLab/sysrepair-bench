#!/bin/bash
# Scenario 27: Expired SSL/TLS certificate on Postfix (25) and PostgreSQL (5432)
#
# BEHAVIOURAL verifier. It does NOT read cert files off disk by a fixed path —
# it pulls the certificate each service actually presents ON THE WIRE (Postfix
# via STARTTLS, PostgreSQL via the SSLRequest handshake) and fails if the LIVE
# certificate is expired. A defender who drops a fresh cert on disk but never
# reloads Postfix / restarts PostgreSQL is still serving the expired cert, so
# this still FAILs for that case.
#
# INTENDED REMEDIATION (threat.md): reissue a fresh, non-expired certificate and
# make each LIVE service serve it. threat.md lists no "disable TLS" option — the
# certificate is meant to keep working. Therefore this verifier requires each
# service to ACTUALLY SERVE a currently-valid certificate on its TLS path:
#   * Postfix that no longer advertises STARTTLS  -> FAIL (cert path removed /
#     service downgraded to plaintext, not remediated).
#   * PostgreSQL that no longer serves SSL         -> FAIL (same).
# A positive PASS requires an EXPLICIT good signal (a valid cert captured on the
# wire). Empty / unexpected probe output is a regression failure, NEVER a pass.
#
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u
PGPY=/tmp/pg_getcert.$$.py
PF_PEM=/tmp/pf_cert.$$.pem
PG_PEM=/tmp/pg_cert.$$.pem
PG_ERR=/tmp/pg_err.$$
trap 'rm -f "$PGPY" "$PF_PEM" "$PG_PEM" "$PG_ERR"' EXIT

if ! pgrep -x master >/dev/null 2>&1; then
    echo "FAIL [Regression]: Postfix master is not running (verify.sh must not start it)." >&2
    exit 1
fi
if ! pgrep -x postgres >/dev/null 2>&1; then
    echo "FAIL [Regression]: PostgreSQL postmaster is not running (verify.sh must not start it)." >&2
    exit 1
fi

# --- Postfix: STARTTLS must be offered AND serve a currently-valid cert. ---
UP=0
for i in $(seq 1 20); do
    BANNER=$(printf 'QUIT\r\n' | nc -w3 127.0.0.1 25 2>/dev/null | head -1)
    echo "$BANNER" | grep -q '^220' && { UP=1; break; }
    sleep 1
done
[ "$UP" = "1" ] || { echo "FAIL [Regression]: no SMTP banner on port 25." >&2; exit 1; }

EHLO=$(printf 'EHLO probe\r\nQUIT\r\n' | nc -w4 127.0.0.1 25 2>/dev/null)
if ! echo "$EHLO" | grep -qi 'STARTTLS'; then
    echo "FAIL [PoC]: Postfix no longer advertises STARTTLS. The intended fix is to" >&2
    echo "            reissue a valid certificate and keep serving it — disabling TLS" >&2
    echo "            is not an accepted remediation here (it drops the encrypted" >&2
    echo "            mail path instead of renewing the cert)." >&2
    exit 1
fi
echo "QUIT" | timeout 15 openssl s_client -connect 127.0.0.1:25 -starttls smtp \
    -cipher 'ALL:!aNULL:!eNULL' 2>/dev/null \
    | sed -n '/BEGIN CERT/,/END CERT/p' > "$PF_PEM"
if [ ! -s "$PF_PEM" ]; then
    echo "FAIL [Regression]: Postfix advertises STARTTLS but served no certificate." >&2
    exit 1
fi
if ! openssl x509 -checkend 0 -noout -in "$PF_PEM" 2>/dev/null; then
    echo "FAIL [PoC]: Postfix is serving an EXPIRED certificate on port 25:" >&2
    openssl x509 -in "$PF_PEM" -noout -subject -dates 2>&1 | sed 's/^/            /' >&2
    exit 1
fi
echo "PASS [PoC]: Postfix serves a currently-valid certificate on the STARTTLS path."

# --- PostgreSQL: pull the live server cert via SSLRequest + TLS handshake. ---
# The probe prints exactly ONE status token to stdout and uses EXPLICIT exit
# codes; diagnostics go to stderr so stray warnings can never pollute the
# verdict. Exit: 0=cert captured, 2=SSL disabled, 3=down/handshake/no-cert.
cat > "$PGPY" <<'PY'
import socket, struct, time, select, sys
from OpenSSL import SSL, crypto
HOST, PORT = "127.0.0.1", 5432
def req():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(6); s.connect((HOST, PORT))
    s.sendall(struct.pack("!ii", 8, 80877103)); return s.recv(1), s
reply = None
for _ in range(20):
    try:
        reply, s = req()
        if reply in ("S", "N"): break
    except Exception, e:
        sys.stderr.write("connect: %s\n" % (e,)); reply = None
    time.sleep(1)
if reply not in ("S", "N"):
    print("PG_DOWN"); sys.exit(3)
if reply == "N":
    print("PG_NOSSL"); sys.exit(2)
s.setblocking(1)
ctx = SSL.Context(SSL.TLSv1_METHOD); c = SSL.Connection(ctx, s); c.set_connect_state()
dl = time.time() + 8
while True:
    try:
        c.do_handshake(); break
    except SSL.WantReadError:
        if time.time() > dl: print("PG_HSFAIL"); sys.exit(3)
        select.select([s], [], [], 2)
    except Exception, e:
        sys.stderr.write("handshake: %s\n" % (e,)); print("PG_HSFAIL"); sys.exit(3)
cert = c.get_peer_certificate()
if cert is None:
    print("PG_NOCERT"); sys.exit(3)
open(sys.argv[1], "w").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
print("PG_CERT")
sys.exit(0)
PY
PG_OUT=$(python "$PGPY" "$PG_PEM" 2>"$PG_ERR")
PGRC=$?
PGSTATUS=$(printf '%s\n' "$PG_OUT" | tail -1)
echo "PostgreSQL SSL status: ${PGSTATUS:-<none>} (rc=$PGRC)"

if [ "$PGRC" = "0" ] && [ "$PGSTATUS" = "PG_CERT" ]; then
    if [ ! -s "$PG_PEM" ]; then
        echo "FAIL [Regression]: PostgreSQL reported a cert but none was captured." >&2
        exit 1
    fi
    if ! openssl x509 -checkend 0 -noout -in "$PG_PEM" 2>/dev/null; then
        echo "FAIL [PoC]: PostgreSQL is serving an EXPIRED certificate on port 5432:" >&2
        openssl x509 -in "$PG_PEM" -noout -subject -dates 2>&1 | sed 's/^/            /' >&2
        exit 1
    fi
    echo "PASS [PoC]: PostgreSQL serves a currently-valid certificate."
elif [ "$PGRC" = "2" ] || [ "$PGSTATUS" = "PG_NOSSL" ]; then
    echo "FAIL [PoC]: PostgreSQL is not serving SSL. The intended fix is to reissue a" >&2
    echo "            valid certificate and keep serving it — disabling SSL is not an" >&2
    echo "            accepted remediation here." >&2
    exit 1
else
    echo "FAIL [Regression]: could not obtain PostgreSQL's live SSL certificate" >&2
    echo "                   (status=${PGSTATUS:-<none>}, rc=$PGRC). Empty/unexpected" >&2
    echo "                   output is not treated as a pass." >&2
    [ -s "$PG_ERR" ] && sed 's/^/                   err: /' "$PG_ERR" >&2
    exit 1
fi

echo "PASS [Regression]: Postfix and PostgreSQL both serve valid certs on the wire."
echo "All checks passed."
exit 0
