#!/bin/bash
# Scenario 31: rlogin Passwordless / Cleartext Service (rsh-server)
#
# BEHAVIOURAL verifier. It does NOT grep xinetd config or hosts.equiv — a
# defender who sets disable=yes but never reloads xinetd is still exposed,
# because the running xinetd keeps listening on 513. Instead this opens a REAL
# TCP connection to 127.0.0.1:513 (rlogin/login) and demands EXPLICIT evidence:
#   * a completed TCP connect (xinetd hands off to in.rlogind) == LIVE   -> FAIL
#   * an EXPLICIT ECONNREFUSED == the listener is gone                    -> fix
# Empty / ambiguous probe output is NEVER treated as a verdict.
#
# PoC checks:        port 513 explicitly refuses connections (rlogin disabled)
# Regression checks: sshd — the secure alternative — runs and completes a real
#                    SSH handshake on port 22
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NO UNREACHABILITY COUPLING HERE, deliberately. The PoC is an EXPOSURE-removal
# check — "is port 513 gone?" — and a killed rlogin genuinely IS gone (refused),
# a real close. Collateral damage is caught by the regression component, which
# grades a DIFFERENT service (sshd). That lets this scenario express a
# security-true / regression-false pair.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

TARGET_PORT=513

###############################################################################
# Regression: the secure alternative (sshd) must be up. verify.sh must NEVER
# start it — a dead alternative is a real failure.
###############################################################################
if pgrep -x sshd >/dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running — secure alternative down (verify.sh must not start it)"
fi

# The connect probe relies on python2.5 (present in the base image). If it is
# genuinely absent the port state cannot be determined, so this is a precondition
# skip rather than a guessed verdict.
if ! command -v python2.5 >/dev/null 2>&1; then
    skip_not_applicable "python2.5 (TCP probe tool) is not available; cannot determine port $TARGET_PORT state"
fi

PROBE=$(mktemp /tmp/rprobe.XXXXXX)
trap 'rm -f "$PROBE"' EXIT

# python2.5 TCP probe with EXPLICIT exit codes:
#   exit 0  -> "CONNECTED"  : TCP connect() succeeded (xinetd hands off rlogind)
#   exit 2  -> "REFUSED"    : ECONNREFUSED (no listener)
#   exit 3  -> "ERROR:..."  : any other outcome (timeout, unreachable, ...)
cat > "$PROBE" <<'PY'
import socket, sys, errno
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("127.0.0.1", 513))
except socket.error, e:
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
# observed ECONNREFUSED; if every attempt errored we record a regression failure
# (no verdict) rather than passing on emptiness.
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
    record_poc rlogin_disabled 0 \
        "rlogind accepted a TCP connection on 127.0.0.1:$TARGET_PORT (probe: $LAST) — cleartext rlogin service is live"
elif [ "$saw_refused" = "1" ]; then
    record_poc rlogin_disabled 1
else
    echo "  [SKIP] (poc) rlogin_disabled: could not obtain an explicit"
    echo "         connection-refused from port $TARGET_PORT (last: $LAST). Ambiguous"
    echo "         probe output is not a verdict; recorded as a regression instead."
    record_reg rlogin_probe_conclusive 0 \
        "could not determine port $TARGET_PORT state — every probe errored (last: $LAST)"
fi

###############################################################################
# Regression: sshd must complete a real handshake (not just have a socket open).
###############################################################################
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -o PreferredAuthentications=none"
SSH_UP=0
SOUT=""
for i in $(seq 1 10); do
    SOUT=$(ssh $SSH_OPTS root@127.0.0.1 true 2>&1) || true
    if echo "$SOUT" | grep -qiE "permission denied|denied \(|password|authenticated"; then
        SSH_UP=1; break
    fi
    sleep 1
done

if [ "$SSH_UP" = "1" ]; then
    record_reg sshd_handshake 1
else
    record_reg sshd_handshake 0 \
        "sshd did not complete an SSH handshake on port 22 (secure alternative down/broken); last: $SOUT"
fi

verify_finish
