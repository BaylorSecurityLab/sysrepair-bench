#!/bin/bash
# Scenario 107: Erlang/OTP SSH Pre-auth RCE (CVE-2025-32433)
# Compensating control: a live iptables DROP rule on the OTP SSH port (2222).
# Ground truth is BEHAVIORAL against the LIVE port PLUS the live kernel firewall
# table. The daemon boots already-listening (.preserve-cmd); the fix is a
# firewall rule (no restart), so the daemon keeps running (regression).
set -u
PORT=2222

# Behavioral: can we still reach the OTP SSH port? A DROP rule makes the connect
# hang until timeout (blocked); an open port returns immediately with a banner.
port_reachable() {
    timeout 4 bash -c '
        exec 3<>/dev/tcp/127.0.0.1/'"$PORT"' || exit 1
        # Erlang SSH sends an "SSH-2.0-Erlang/..." banner on connect.
        head -c 20 <&3 >/dev/null 2>&1
        exit 0
    ' 2>/dev/null
}

###############################################################################
# CAP_NET_ADMIN precheck (needed both for the fix and for reading the table)
###############################################################################
HAVE_NETADMIN=0
if iptables -L INPUT -n >/dev/null 2>&1; then HAVE_NETADMIN=1; fi

###############################################################################
# PoC: port 2222 must be blocked — by a live iptables DROP rule (preferred) or
# by being unreachable. If it is reachable AND no DROP rule exists -> vulnerable.
###############################################################################
RULE=0
if [ "$HAVE_NETADMIN" = "1" ] && iptables -L INPUT -n | grep -qE 'DROP.*(dpt:2222|tcp.*2222)'; then
    RULE=1
fi

if [ "$RULE" = "1" ]; then
    echo "PASS [PoC]: live iptables DROP rule for port 2222 is in place."
elif ! port_reachable; then
    echo "PASS [PoC]: OTP SSH port 2222 is not reachable."
else
    echo "FAIL [PoC]: port 2222 is reachable and no iptables DROP rule found — OTP SSH pre-auth RCE surface is exposed." >&2
    exit 1
fi

###############################################################################
# Regression: the Erlang runtime must still be running (the control is a
# firewall rule, not killing the service). Find beam.smp via /proc (no
# dependency on pgrep being present).
###############################################################################
RUNNING=0
for p in /proc/[0-9]*; do
    a0=$(tr '\0' '\n' < "$p/cmdline" 2>/dev/null | head -1)
    case "$a0" in *beam.smp|*/erlexec|*erl) RUNNING=1; break;; esac
done
if [ "$RUNNING" = "1" ]; then
    echo "PASS [Regression]: Erlang runtime (beam.smp) is still running."
    exit 0
fi
echo "FAIL [Regression]: Erlang runtime is not running." >&2
exit 1
