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
#   * The probe never trusts a single client binary. `/bin/nc.traditional` is
#     only the FIRST method tried; if a defender DELETES the client binary
#     (which does NOT kill the already-listening backdoor) we fall back to nc
#     and then to a raw python socket, so the live shell is still reached. An
#     empty read is NEVER read as "safe".
#   * If NO probe tool exists at all, that is an ERROR/FAIL, never a PASS.
#   * PASS requires POSITIVE proof the backdoor is gone (no MARKER returned from
#     any live listener), not merely the absence of output.
#
#   backdoor listener alive          -> MARKER returned -> FAIL
#   listener killed + script removed -> no MARKER        -> PASS
#   script deleted but nc still up   -> MARKER returned -> FAIL (live process)
#   nc.traditional deleted, nc up    -> MARKER returned -> FAIL (python fallback)
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.

set -u

MARKER="INGRES_${$}_${RANDOM}_OK"

TARGETS="127.0.0.1"
IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -z "${IP:-}" ] && IP=$(hostname -i 2>/dev/null | awk '{print $1}')
case "${IP:-}" in 127.*|"") ;; *) TARGETS="$TARGETS $IP" ;; esac

###############################################################################
# Regression FIRST: sshd is the legitimate management channel and must stay up.
# verify.sh must NEVER start it — a dead box is a real failure.
###############################################################################
if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "FAIL [Regression]: sshd is not running — a dead management channel is a" >&2
    echo "                   failure (verify.sh must not start it)." >&2
    exit 1
fi
if ! netstat -ln 2>/dev/null | grep -q ':22 '; then
    echo "FAIL [Regression]: sshd is not listening on port 22." >&2
    exit 1
fi

###############################################################################
# Guard: a probe tool MUST exist. Missing tool => ERROR/FAIL, never PASS —
# otherwise deleting the client would blind the check into a false "safe".
###############################################################################
HAVE_PROBE=0
[ -x /bin/nc.traditional ] && HAVE_PROBE=1
command -v nc >/dev/null 2>&1 && HAVE_PROBE=1
command -v python >/dev/null 2>&1 && HAVE_PROBE=1
if [ "$HAVE_PROBE" != "1" ]; then
    echo "FAIL [Error]: no probe tool (nc.traditional / nc / python) available to" >&2
    echo "              exercise port 1524 — cannot prove the backdoor is gone." >&2
    exit 1
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

for t in $TARGETS; do
    # Retry to avoid a false PASS on a merely slow/respawning listener.
    for i in 1 2 3; do
        OUT=$(exploit_once "$t")
        if echo "$OUT" | grep -q "$MARKER"; then
            echo "FAIL [PoC]: connected to ${t}:1524 and the live backdoor EXECUTED our" >&2
            echo "            command (unique marker returned) — unauthenticated shell:" >&2
            echo "            $(echo "$OUT" | tr -d '\r' | grep -E 'uid=|'"$MARKER" | head -2 | tr '\n' ' ')" >&2
            exit 1
        fi
        sleep 1
    done
done
echo "PASS [PoC]: no command execution reachable on port 1524 (backdoor gone)."

###############################################################################
# Regression: SSH management channel still answers.
###############################################################################
if ! pgrep -x sshd >/dev/null 2>&1 || ! netstat -ln 2>/dev/null | grep -q ':22 '; then
    echo "FAIL [Regression]: sshd no longer available on port 22." >&2
    exit 1
fi
echo "PASS [Regression]: sshd management channel still listening on port 22."

echo "All checks passed."
exit 0
