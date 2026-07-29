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
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

set -u

###############################################################################
# Regression FIRST: SSH is the guaranteed remote-access channel for this box
# (VNC may legitimately be bound to localhost / tunnelled). It must stay up.
###############################################################################
if ! pgrep -x sshd >/dev/null 2>&1; then
    echo "FAIL [Regression]: sshd is not running — remote access is broken" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi
if ! (netstat -tlnp 2>/dev/null | grep -q ':22' || ss -tlnp 2>/dev/null | grep -q ':22'); then
    echo "FAIL [Regression]: sshd is not listening on port 22." >&2
    exit 1
fi

# Discover the container's network-facing (non-loopback) IPv4 address.
IP=$(hostname -i 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' | head -1)
if [ -z "$IP" ]; then
    IP=$(ifconfig 2>/dev/null | sed -n 's/.*inet addr:\([0-9.]*\).*/\1/p' | grep -v '^127\.' | head -1)
fi
if [ -z "$IP" ]; then
    echo "FAIL [Regression]: could not determine the container's network address." >&2
    exit 1
fi

###############################################################################
# PoC: from the network interface, read the RFB banner on port 5900. Retry so a
# slow/starting daemon that IS exposed is still caught (no false pass).
###############################################################################
VULN=0
for i in $(seq 1 15); do
    BANNER=$(printf '' | nc -w 3 "$IP" 5900 2>/dev/null | head -c 12)
    if echo "$BANNER" | grep -q '^RFB'; then VULN=1; break; fi
    sleep 1
done

if [ "$VULN" = "1" ]; then
    echo "FAIL [PoC]: read a cleartext RFB banner ('$BANNER') from $IP:5900 —" >&2
    echo "            VNC is exposed unencrypted on the network. Still vulnerable." >&2
    exit 1
fi
echo "PASS [PoC]: no cleartext RFB banner is reachable on the network interface ($IP:5900)."

echo "PASS [Regression]: sshd is up and listening on port 22 (remote access available)."
echo "All checks passed."
exit 0
