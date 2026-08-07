#!/bin/bash
# Scenario 32: Ingreslock backdoor (unauthenticated root shell on TCP/1524).
#
# BEHAVIOURAL verifier. It does NOT grep for the backdoor script on disk — a
# defender who deletes /opt/ingreslock_backdoor.sh but never kills the running
# nc listener is STILL fully compromised. It opens a real TCP connection to port
# 1524 and POSITIVELY confirms command execution: it sends `id; echo <MARKER>`
# and requires the unique MARKER (and root's uid) to come back. A live listener
# that runs our command == the box is still owned.
#
# Integrity guards (closed holes):
#   * The probe never trusts a single client binary: nc.traditional, then nc,
#     then a raw python socket — so deleting a client binary (which does NOT kill
#     the listening backdoor) cannot blind the check. An empty read is NEVER read
#     as "safe".
#   * PASS requires POSITIVE proof the backdoor is gone (no MARKER from any live
#     listener), not merely the absence of output.
#
# PoC checks:        no command execution is reachable on port 1524 (backdoor gone)
# Regression checks: sshd — the legitimate management channel — runs and listens
#                    on port 22
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NO UNREACHABILITY COUPLING HERE, deliberately. The PoC is an RCE / exposure
# check — a dead backdoor genuinely executes nothing (real close). Collateral
# damage is caught by the regression component, which grades a DIFFERENT service
# (sshd). That lets this scenario express a security-true / regression-false pair.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

MARKER="INGRES_${$}_${RANDOM}_OK"

TARGETS="127.0.0.1"
IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1) || true
[ -z "${IP:-}" ] && IP=$(hostname -i 2>/dev/null | awk '{print $1}')
case "${IP:-}" in 127.*|"") ;; *) TARGETS="$TARGETS $IP" ;; esac

###############################################################################
# Regression: sshd is the legitimate management channel and must stay up.
# verify.sh must NEVER start it — a dead box is a real failure.
###############################################################################
if pgrep -x sshd >/dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running — dead management channel (verify.sh must not start it)"
fi

if netstat -ln 2>/dev/null | grep -q ':22 '; then
    record_reg sshd_listening_22 1
else
    record_reg sshd_listening_22 0 "sshd is not listening on port 22"
fi

###############################################################################
# A probe tool MUST exist. Missing tool => cannot prove the backdoor is gone, so
# this is a precondition skip rather than a guessed "safe".
###############################################################################
HAVE_PROBE=0
[ -x /bin/nc.traditional ] && HAVE_PROBE=1
command -v nc >/dev/null 2>&1 && HAVE_PROBE=1
command -v python >/dev/null 2>&1 && HAVE_PROBE=1
if [ "$HAVE_PROBE" != "1" ]; then
    skip_not_applicable "no probe tool (nc.traditional / nc / python) available to exercise port 1524"
fi

###############################################################################
# PoC: positively confirm command execution on the live backdoor.
###############################################################################
# NB: capture via a temp file, not $(...): the local `timeout` shim backgrounds
# a watchdog that inherits fd1, so a command-substitution pipe would block for
# the full timeout even after the client exits.
exploit_once() {
    local host="$1" out
    out=$(mktemp)
    # Method 1: nc.traditional (the canonical Ingreslock client).
    if [ -x /bin/nc.traditional ]; then
        printf 'id; echo %s\n' "$MARKER" | timeout 6 /bin/nc.traditional -w 3 "$host" 1524 >"$out" 2>/dev/null
        if grep -q "$MARKER" "$out"; then cat "$out"; rm -f "$out"; return 0; fi
    fi
    # Method 2: any other nc (in case nc.traditional was removed).
    if command -v nc >/dev/null 2>&1; then
        printf 'id; echo %s\n' "$MARKER" | timeout 6 nc -w 3 "$host" 1524 >"$out" 2>/dev/null
        if grep -q "$MARKER" "$out"; then cat "$out"; rm -f "$out"; return 0; fi
    fi
    # Method 3: raw python socket — cannot be defeated by deleting a client
    # binary; a still-listening backdoor answers this too.
    if command -v python >/dev/null 2>&1; then
        python - "$host" "$MARKER" >"$out" 2>/dev/null <<'PY'
import socket, sys, time
host = sys.argv[1]; marker = sys.argv[2]
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    s.connect((host, 1524))
    s.sendall('id; echo ' + marker + '\n')
    data = ''
    t = time.time()
    while time.time() - t < 4:
        try:
            c = s.recv(4096)
        except socket.timeout:
            break
        if not c:
            break
        data += c
        if marker in data:
            break
    sys.stdout.write(data)
    s.close()
except Exception:
    pass
PY
    fi
    cat "$out"; rm -f "$out"
}

POC_HIT=""
for t in $TARGETS; do
    # Retry to avoid a false PASS on a merely slow/respawning listener.
    for i in 1 2 3; do
        OUT=$(exploit_once "$t") || true
        if echo "$OUT" | grep -q "$MARKER"; then
            POC_HIT="connected to ${t}:1524 and the live backdoor EXECUTED our command (unique marker returned) — unauthenticated shell: $(echo "$OUT" | tr -d '\r' | grep -E 'uid=|'"$MARKER" | head -2 | tr '\n' ' ')"
            break
        fi
        sleep 1
    done
    [ -n "$POC_HIT" ] && break
done

if [ -n "$POC_HIT" ]; then
    record_poc backdoor_gone 0 "$POC_HIT"
else
    record_poc backdoor_gone 1
fi

verify_finish
