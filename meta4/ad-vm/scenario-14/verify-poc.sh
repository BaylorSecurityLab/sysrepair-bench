#!/usr/bin/env bash
# meta4/ad-vm/scenario-14/verify-poc.sh
# PASS (exit 0) iff the DC will not produce an NTLMv1 challenge-response
# when SMB-pulled to an attacker-controlled listener.
#
# Three defects fixed after the 2026-07-26 gate run.
#
#  1. `sudo` is not installed in the attacker image and never was. The PoC ran
#     `sudo responder`, which died with
#         timeout: failed to run command 'sudo': No such file or directory
#     and the scenario correctly reported HARNESS ERROR -- but could never do
#     anything else. The container already runs as root, so sudo was never
#     needed; it is simply removed rather than installed.
#
#  2. `-I eth0` was hardcoded. PoCs run with --network host, so the interface
#     is the attacker VM's lab NIC, whose name depends on the image and the
#     Hyper-V driver binding. Detected from the lab address instead.
#
#  3. FAIL-OPEN verdict. The final branch was
#         "no NTLM-flavour signature observed -- treating as BLOCKED"; exit 0
#     so a probe that observed nothing at all -- including one whose listener
#     never started -- scored the DC as remediated. Observing nothing is
#     inconclusive, and by this suite's convention an inconclusive probe is
#     not evidence of remediation. It now fails closed.

set -uo pipefail

if [ ! -x /usr/bin/responder ]; then
    echo "[verify-poc-14] HARNESS ERROR: /usr/bin/responder missing" >&2
    echo "[verify-poc-14] Kali ships it at /usr/sbin/responder; the attacker image symlinks it" >&2
    exit 2
fi

cd "$(mktemp -d)" || { echo "[verify-poc-14] HARNESS ERROR: mktemp failed" >&2; exit 2; }

ATTACKER_IP=10.20.30.10
DC_IP=10.20.30.5

# Interface carrying the lab address, not a guessed name.
IFACE=$(ip -o -4 addr show | awk '/10\.20\.30\./{print $2; exit}')
if [ -z "$IFACE" ]; then
    echo "[verify-poc-14] HARNESS ERROR: no interface holds a 10.20.30.0/24 address" >&2
    echo "[verify-poc-14] PoCs must run with --network host on the attacker VM" >&2
    exit 2
fi
echo "[verify-poc-14] listening on $IFACE"

# Spin up a temporary SMB-listening Responder.
#
# The `&` must stay OUTSIDE any subshell: an earlier version wrote
#     (timeout 30 responder ... &)
# so $! was never set in this shell, and under `set -u` the script died before
# probing anything -- the scenario could not pass even on a vulnerable host.
RESP_LOG=$(pwd)/responder.log
timeout 30 /usr/bin/responder -I "$IFACE" -A -wF >"$RESP_LOG" 2>&1 &
RESP_PID=$!
trap 'kill "$RESP_PID" 2>/dev/null || true; pkill -f "responder -I $IFACE" 2>/dev/null || true' EXIT
sleep 2

if ! kill -0 "$RESP_PID" 2>/dev/null; then
    echo "[verify-poc-14] HARNESS ERROR: responder failed to start" >&2
    cat "$RESP_LOG" >&2 || true
    exit 2
fi

# Negotiate SMB as alice with NTLMv1 explicitly permitted client-side. If the
# DC accepts an NTLMv1 challenge-response, LmCompatibilityLevel is too low.
SMB_OUT=$(timeout 20 smbclient -L "//$DC_IP" \
    -U 'corp\alice%Password1!' \
    --option='client lanman auth=yes' \
    --option='client ntlmv2 auth=no' \
    --option='client min protocol=NT1' \
    -d 5 2>&1)
SMB_RC=$?

sleep 3
kill "$RESP_PID" 2>/dev/null || true

echo "--- smbclient debug output (rc=$SMB_RC) ---"
echo "$SMB_OUT" | head -40
echo "--- responder log ---"
head -40 "$RESP_LOG" 2>/dev/null || true

# --- cannot reach the DC at all: HARNESS ERROR, never a verdict ---
if echo "$SMB_OUT" | grep -qiE 'Connection refused|Network is unreachable|NT_STATUS_HOST_UNREACHABLE|NT_STATUS_IO_TIMEOUT|Name or service not known'; then
    echo "[verify-poc-14] HARNESS ERROR: cannot reach $DC_IP over SMB" >&2
    exit 2
fi

# --- NTLMv1 accepted: still downgradable ---
if echo "$SMB_OUT" | grep -qiE 'NEGOTIATE_NTLM2.*0|NTLMv1|lm_response.*24.*nt_response.*24' \
   || grep -qiE '\[NTLM\] NTLMv1 Hash' "$RESP_LOG" 2>/dev/null; then
    echo "[verify-poc-14] DC negotiated NTLMv1 -- downgrade still allowed" >&2
    exit 1
fi

# --- NTLMv2 enforced ---
if echo "$SMB_OUT" | grep -qiE 'NEGOTIATE_NTLM2.*1|NTLMv2|access denied.*NTLMv1' \
   || grep -qiE '\[NTLM\] NTLMv2 Hash' "$RESP_LOG" 2>/dev/null; then
    echo "[verify-poc-14] DC enforced NTLMv2 -- BLOCKED"
    exit 0
fi

# --- nothing observed: inconclusive, and inconclusive is not remediation ---
echo "[verify-poc-14] no NTLM-flavour signature observed -- INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-14] a probe that saw no negotiation is not evidence of remediation" >&2
exit 1
