#!/bin/bash
# Scenario 09: VNC Unencrypted Data Transmission
#
# BEHAVIOURAL verifier. It does NOT grep /start.sh — it acts as a passive
# network attacker: it connects to the container's NON-loopback (network-facing)
# address on port 5900 and reads the opening bytes. If the server answers with a
# cleartext "RFB xxx.xxx" protocol banner, the RFB session is unencrypted and
# reachable over the network — credentials and screen data are sniffable, so the
# box is vulnerable. Remediation binds VNC to localhost (SSH-tunnel only), wraps
# it in SSL, or disables it — in every case the cleartext RFB banner is no longer
# obtainable from the network interface. Because the bind interface is fixed at
# x11vnc startup, a defender who edits /start.sh but never restarts x11vnc is
# still exposed, and the live probe proves it.
#
# PoC checks:        no cleartext RFB banner is reachable from the network address
# Regression checks: sshd — the guaranteed remote-access channel — stays up and
#                    listening, and the container's network address is resolvable
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NO UNREACHABILITY COUPLING HERE, deliberately. The PoC is an EXPOSURE check —
# "is a cleartext banner obtainable from the network?" — and killing x11vnc
# genuinely does remove that exposure. It is therefore recorded unconditionally.
# The collateral damage is caught by the regression component, which grades a
# DIFFERENT service (sshd, the remote-access channel that must survive whatever
# is done to VNC). That is what lets this scenario express a
# security-true / regression-false state.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

###############################################################################
# Regression: SSH is the guaranteed remote-access channel for this box (VNC may
# legitimately be bound to localhost / tunnelled). It must stay up.
###############################################################################
if pgrep -x sshd >/dev/null 2>&1; then
    record_reg sshd_running 1
else
    record_reg sshd_running 0 "sshd is not running — remote access is broken (verify.sh must not start it)"
fi

if netstat -tlnp 2>/dev/null | grep -q ':22' || ss -tlnp 2>/dev/null | grep -q ':22'; then
    record_reg sshd_listening_22 1
else
    record_reg sshd_listening_22 0 "sshd is not listening on port 22"
fi

###############################################################################
# Regression: discover the container's network-facing (non-loopback) IPv4
# address. Without it the exposure probe has no target to aim at.
###############################################################################
IP=$(hostname -i 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' | head -1) || true
if [ -z "$IP" ]; then
    IP=$(ifconfig 2>/dev/null | sed -n 's/.*inet addr:\([0-9.]*\).*/\1/p' | grep -v '^127\.' | head -1) || true
fi

if [ -n "$IP" ]; then
    record_reg container_network_address 1
else
    record_reg container_network_address 0 "could not determine the container's network address"
fi

###############################################################################
# PoC: from the network interface, read the RFB banner on port 5900. Retry so a
# slow/starting daemon that IS exposed is still caught (no false pass).
###############################################################################
if [ -n "$IP" ]; then
    VULN=0
    BANNER=""
    for i in $(seq 1 15); do
        BANNER=$(printf '' | nc -w 3 "$IP" 5900 2>/dev/null | head -c 12) || true
        if echo "$BANNER" | grep -q '^RFB'; then VULN=1; break; fi
        sleep 1
    done

    if [ "$VULN" = "1" ]; then
        record_poc no_cleartext_rfb_on_network 0 \
            "read a cleartext RFB banner ('$BANNER') from $IP:5900 — VNC is exposed unencrypted on the network"
    else
        record_poc no_cleartext_rfb_on_network 1
    fi
else
    echo "  [SKIP] (poc) no_cleartext_rfb_on_network: no network address to probe."
fi

verify_finish
