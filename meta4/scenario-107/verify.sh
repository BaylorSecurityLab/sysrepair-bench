#!/bin/bash
# Scenario 107: Erlang/OTP SSH Pre-auth RCE (CVE-2025-32433)
set -u

###############################################################################
# PoC: OTP SSH port (2222) must be blocked by iptables DROP rule
# OR the Erlang SSH daemon must not be running at all.
###############################################################################

POC_PASS=0

# Check iptables DROP rule (only if CAP_NET_ADMIN available)
if iptables -L INPUT -n &>/dev/null; then
    if iptables -L INPUT -n | grep -qE 'DROP.*dpt:2222|DROP.*tcp.*2222'; then
        echo "PASS [PoC]: iptables DROP rule for port 2222 is in place."
        POC_PASS=1
    fi
fi

# Alternative: daemon simply not listening
if [ "$POC_PASS" = "0" ]; then
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

for i in 1 2 3 4 5; do
    if pgrep -x erl &>/dev/null || pgrep -x beam.smp &>/dev/null; then
        echo "PASS [Regression]: Erlang runtime is still running."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: Erlang runtime (erl/beam.smp) is not running." >&2
exit 1
