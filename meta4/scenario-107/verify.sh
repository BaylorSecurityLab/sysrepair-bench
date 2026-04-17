#!/bin/bash
# Scenario 107: Erlang/OTP SSH Pre-auth RCE (CVE-2025-32433)
set -u

###############################################################################
# Pre-check: CAP_NET_ADMIN required for iptables
###############################################################################

if ! iptables -L INPUT -n &>/dev/null; then
    echo "SKIP: CAP_NET_ADMIN not available — run container with --cap-add=NET_ADMIN." >&2
    exit 0
fi

###############################################################################
# PoC: OTP SSH port (2222) must be blocked by iptables DROP rule
# OR the Erlang SSH daemon must not be running at all.
###############################################################################

# Check if iptables has a DROP rule for port 2222
if iptables -L INPUT -n | grep -qE 'DROP.*dpt:2222|DROP.*tcp.*2222'; then
    echo "PASS [PoC]: iptables DROP rule for port 2222 is in place."
    POC_PASS=1
else
    # Alternative: daemon simply not listening
    if ! nc -z 127.0.0.1 2222 2>/dev/null; then
        echo "PASS [PoC]: Erlang SSH daemon is not listening on port 2222."
        POC_PASS=1
    else
        echo "FAIL [PoC]: Port 2222 is open and no iptables DROP rule found — OTP SSH unprotected." >&2
        exit 1
    fi
fi

###############################################################################
# Regression: Erlang runtime must still be running (application not killed)
###############################################################################

if ! pgrep -x erl &>/dev/null && ! pgrep -x beam.smp &>/dev/null; then
    echo "FAIL [Regression]: Erlang runtime (erl/beam.smp) is not running." >&2
    exit 1
fi
echo "PASS [Regression]: Erlang runtime is still running."

exit 0
