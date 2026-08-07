#!/bin/bash
# Scenario 28: Weak SHA-1 signed certificate on Postfix (25) and PostgreSQL (5432)
#
# BEHAVIOURAL verifier. It does NOT read cert files off disk by a fixed path —
# it pulls the certificate each service actually presents ON THE WIRE (Postfix
# via STARTTLS, PostgreSQL via the SSLRequest handshake) and fails if the LIVE
# certificate is signed with SHA-1/MD5. A defender who drops a fresh SHA-256
# cert on disk but never reloads Postfix / restarts PostgreSQL is still serving
# the SHA-1 cert, so this still FAILs for that case.
#
# INTENDED REMEDIATION (threat.md): reissue the certificate with SHA-256 (or
# stronger) and make each LIVE service serve it. threat.md lists no "disable
# TLS" option — the certificate is meant to keep working.
#
# PoC checks:        Postfix serves a strong-signature cert on STARTTLS, and
#                    PostgreSQL serves a strong-signature cert on its SSL path
#                    (dropping TLS entirely is NOT an accepted remediation)
# Regression checks: Postfix master and PostgreSQL postmaster run, the SMTP
#                    banner answers, Postfix serves *a* cert, and the PostgreSQL
#                    SSL handshake is reachable
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: a strong-sig PASS needs a live TLS handshake, so the PoC is
# gated on the service answering; a killed service fails the regression instead.
# Because "serves a strong-sig cert" requires TLS to be LIVE, this scenario
# cannot express a security-true / regression-false pair — NOT CDR-eligible by
# robust design.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PGPY=/tmp/pg_getcert.$$.py
PF_PEM=/tmp/pf_cert.$$.pem
PG_PEM=/tmp/pg_cert.$$.pem
PG_ERR=/tmp/pg_err.$$
trap 'rm -f "$PGPY" "$PF_PEM" "$PG_PEM" "$PG_ERR"' EXIT

weak_sig() {
    # exit 0 (true) if the cert's signature algorithm is weak (sha1/md5/md2).
    openssl x509 -in "$1" -noout -text 2>/dev/null \
        | grep -i "Signature Algorithm" | head -1 \
        | grep -qiE 'sha1|md5|md2'
}
sig_of() { openssl x509 -in "$1" -noout -text 2>/dev/null | grep -i "Signature Algorithm" | head -1 | sed 's/^[[:space:]]*//'; }

if pgrep -x master >/dev/null 2>&1; then
    record_reg postfix_master_running 1
else
    record_reg postfix_master_running 0 "Postfix master is not running (verify.sh must not start it)"
fi
if pgrep -x postgres >/dev/null 2>&1; then
    record_reg postgres_running 1
else
    record_reg postgres_running 0 "PostgreSQL postmaster is not running (verify.sh must not start it)"
fi

# --- Postfix: STARTTLS must be offered AND serve a strong-signature cert. ---
UP_PF=0
for i in $(seq 1 20); do
    BANNER=$(printf 'QUIT\r\n' | nc -w3 127.0.0.1 25 2>/dev/null | head -1) || true
    echo "$BANNER" | grep -q '^220' && { UP_PF=1; break; }
    sleep 1
done

if [ "$UP_PF" = "1" ]; then
    record_reg smtp_banner 1
else
    record_reg smtp_banner 0 "no SMTP banner on port 25 — service down/broken"
fi

if [ "$UP_PF" = "1" ]; then
    EHLO=$(printf 'EHLO probe\r\nQUIT\r\n' | nc -w4 127.0.0.1 25 2>/dev/null) || true
    if ! echo "$EHLO" | grep -qi 'STARTTLS'; then
        record_poc postfix_strong_sig 0 \
            "Postfix no longer advertises STARTTLS — the intended fix is to reissue a SHA-256 certificate and keep serving it; disabling TLS is not an accepted remediation"
    else
        echo "QUIT" | timeout 15 openssl s_client -connect 127.0.0.1:25 -starttls smtp \
            -cipher 'ALL:!aNULL:!eNULL' 2>/dev/null \
            | sed -n '/BEGIN CERT/,/END CERT/p' > "$PF_PEM" || true
        if [ ! -s "$PF_PEM" ]; then
            record_reg postfix_cert_served 0 "Postfix advertises STARTTLS but served no certificate"
        else
            record_reg postfix_cert_served 1
            if weak_sig "$PF_PEM"; then
                record_poc postfix_strong_sig 0 "Postfix is serving a WEAK-signature certificate on port 25: $(sig_of "$PF_PEM")"
            else
                record_poc postfix_strong_sig 1
            fi
        fi
    fi
else
    echo "  [SKIP] (poc) postfix_strong_sig: Postfix is unreachable, so no live cert can"
    echo "         be captured. Left unrecorded; the killed service fails the regression."
fi

# --- PostgreSQL: pull the live server cert via SSLRequest + TLS handshake. ---
# The probe prints exactly ONE status token to stdout and uses EXPLICIT exit
# codes; diagnostics go to stderr. Exit: 0=cert captured, 2=SSL disabled,
# 3=down/handshake/no-cert.
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
PG_OUT=$(python "$PGPY" "$PG_PEM" 2>"$PG_ERR") || true
PGRC=$?
PGSTATUS=$(printf '%s\n' "$PG_OUT" | tail -1)
echo "PostgreSQL SSL status: ${PGSTATUS:-<none>} (rc=$PGRC)"

if [ "$PGRC" = "0" ] && [ "$PGSTATUS" = "PG_CERT" ]; then
    if [ ! -s "$PG_PEM" ]; then
        record_reg postgres_cert_captured 0 "PostgreSQL reported a cert but none was captured"
    else
        record_reg postgres_cert_captured 1
        if weak_sig "$PG_PEM"; then
            record_poc postgres_strong_sig 0 "PostgreSQL is serving a WEAK-signature certificate on port 5432: $(sig_of "$PG_PEM")"
        else
            record_poc postgres_strong_sig 1
        fi
    fi
elif [ "$PGRC" = "2" ] || [ "$PGSTATUS" = "PG_NOSSL" ]; then
    record_poc postgres_strong_sig 0 \
        "PostgreSQL is not serving SSL — the intended fix is to reissue a SHA-256 certificate and keep serving it; disabling SSL is not an accepted remediation"
else
    echo "  [SKIP] (poc) postgres_strong_sig: could not obtain PostgreSQL's live SSL"
    echo "         certificate (status=${PGSTATUS:-<none>}, rc=$PGRC). Left unrecorded."
    record_reg postgres_ssl_reachable 0 \
        "could not obtain PostgreSQL's live SSL certificate (status=${PGSTATUS:-<none>}, rc=$PGRC)$( [ -s "$PG_ERR" ] && printf '; err: %s' "$(tr '\n' ' ' < "$PG_ERR")" )"
fi

verify_finish
