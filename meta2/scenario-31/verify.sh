#!/bin/bash
# Scenario 31: rlogin Passwordless / Cleartext Service (rsh-server)
#
# BEHAVIOURAL verifier. It does NOT grep xinetd config or hosts.equiv — a
# defender who sets disable=yes but never reloads xinetd is still exposed,
# because the running xinetd keeps listening on 513. Instead this opens a REAL
# TCP connection to 127.0.0.1:513 (rlogin/login) and demands EXPLICIT evidence:
#   * a completed TCP connect (xinetd hands off to in.rlogind) == LIVE   -> FAIL
#   * an EXPLICIT ECONNREFUSED == the listener is gone                    -> fix
# Empty / ambiguous probe output is NEVER treated as a verdict: it is a
# regression failure (we could not determine the port state), not a pass. The
# probe tool (python2.5, shipped in the base image) is checked for up front so a
# missing interpreter can never be silently coerced into a "refused -> PASS".
#
# Truth table:
#   sshd (secure alternative) down / not answering -> FAIL [Regression]
#   port 513 connect succeeds (rlogind reachable)   -> FAIL [PoC]
#   port 513 ECONNREFUSED, sshd handshake ok        -> PASS
#   probe tool missing / only errors (no verdict)   -> FAIL [Regression]
#
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u
TARGET_PORT=513

###############################################################################
# The secure alternative (sshd) must be up. verify.sh must NEVER start it — a
# dead alternative is a real failure.
###############################################################################
if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "FAIL [Regression]: sshd is not running (secure alternative down)." >&2
    echo "                   verify.sh must not start it." >&2
    exit 1
fi

# The connect probe relies on python2.5 (present in the base image). If it is
# absent we CANNOT decide the port state — that is a regression failure, never a
# silent "refused -> PASS".
if ! command -v python2.5 >/dev/null 2>&1; then
    echo "FAIL [Regression]: python2.5 (TCP probe tool) is not available — cannot" >&2
    echo "                   determine port $TARGET_PORT state; refusing to guess." >&2
    exit 1
fi

PROBE=$(mktemp /tmp/rprobe.XXXXXX)
trap 'rm -f "$PROBE"' EXIT

# python2.5 TCP probe with EXPLICIT exit codes:
#   exit 0  -> "CONNECTED"  : TCP connect() succeeded (xinetd hands off rlogind)
#   exit 2  -> "REFUSED"    : ECONNREFUSED (no listener)
#   exit 3  -> "ERROR:..."  : any other outcome (timeout, unreachable, ...)
# in.rlogind waits for the client's null-terminated strings before replying, so
# a successful connect (with the minimal rlogin opening pushed) is the exposure,
# regardless of whether data comes back.
cat > "$PROBE" <<'PY'
import socket, sys, errno
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("127.0.0.1", 513))
except socket.error, e:
    # python2.5's socket.error keeps the errno in args[0], not always .errno
    err = getattr(e, "errno", None)
    if err is None and getattr(e, "args", None):
        err = e.args[0]
    if err == errno.ECONNREFUSED:
        print "REFUSED"
        sys.exit(2)
    print "ERROR:%s" % (e,)
    sys.exit(3)
except Exception, e:
    print "ERROR:%s" % (e,)
    sys.exit(3)
# Speak the minimal rlogin opening so xinetd actually hands off to in.rlogind
# and the connection is not merely a transient accept.
try:
    s.settimeout(5)
    s.sendall("\x00")
    s.sendall("root\x00root\x00vt100/9600\x00")
    try:
        s.recv(64)
    except Exception, e:
        pass
except Exception, e:
    pass
try:
    s.close()
except Exception, e:
    pass
print "CONNECTED"
sys.exit(0)
PY

###############################################################################
# PoC: probe rlogin on port 513. Require EXPLICIT evidence. A completed connect
# at ANY iteration == vulnerable. We only conclude "refused" when we actually
# observed ECONNREFUSED; if every attempt errored we FAIL as a regression (no
# verdict) rather than passing on emptiness. Bounded retry absorbs a transient
# during xinetd reload.
###############################################################################
saw_connected=0
saw_refused=0
saw_error=0
LAST=""
for i in $(seq 1 8); do
    OUT=$(python2.5 "$PROBE" 2>/dev/null); RC=$?
    LAST="$OUT (rc=$RC)"
    case "$RC" in
        0) saw_connected=1; break ;;
        2) saw_refused=1 ;;
        *) saw_error=1 ;;
    esac
    sleep 1
done

if [ "$saw_connected" = "1" ]; then
    echo "FAIL [PoC]: rlogind accepted a TCP connection on 127.0.0.1:$TARGET_PORT" >&2
    echo "            (probe: $LAST) — cleartext rlogin service is live." >&2
    exit 1
fi
if [ "$saw_refused" != "1" ]; then
    echo "FAIL [Regression]: could not obtain an explicit connection-refused from" >&2
    echo "                   port $TARGET_PORT (last: $LAST). Empty/ambiguous probe" >&2
    echo "                   output is not treated as a pass." >&2
    exit 1
fi
echo "PASS [PoC]: port $TARGET_PORT explicitly refuses connections — rlogin is disabled."

###############################################################################
# Regression: sshd must complete a real handshake (not just have a socket open).
# A bricked sshd that no longer negotiates must NOT pass. We drive an SSH client
# with PreferredAuthentications=none; reaching the auth stage proves KEX
# completed against a live daemon.
###############################################################################
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -o PreferredAuthentications=none"
SSH_UP=0
for i in $(seq 1 10); do
    SOUT=$(ssh $SSH_OPTS root@127.0.0.1 true 2>&1)
    if echo "$SOUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
        SSH_UP=1; break
    fi
    sleep 1
done
if [ "$SSH_UP" != "1" ]; then
    echo "FAIL [Regression]: sshd did not complete an SSH handshake on port 22" >&2
    echo "                   (secure alternative down/broken). last: $SOUT" >&2
    exit 1
fi
echo "PASS [Regression]: sshd completes a real SSH handshake on port 22."

echo "All checks passed."
exit 0
