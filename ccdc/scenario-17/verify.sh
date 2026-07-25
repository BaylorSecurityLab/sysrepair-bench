#!/bin/bash
# Scenario 17: BIND DNS zone transfer unrestricted
# Verification: PoC should fail (zone transfer denied) AND functionality test should pass

PASS=true

# --- PoC Test: Zone transfers should be restricted ---
# Check named.conf.options for allow-transfer
TRANSFER=$(grep -rE 'allow-transfer' /etc/bind/named.conf.options /etc/bind/named.conf.local 2>/dev/null | grep -v '#')
if echo "$TRANSFER" | grep -q 'any'; then
    echo "FAIL [PoC]: allow-transfer is set to 'any'"
    PASS=false
else
    echo "PASS [PoC]: allow-transfer is restricted"
fi

# --- PoC Behavioral Test: Zone transfer MUST be denied (mandatory) ---
# NOTE: this verifier deliberately has NO "start named if it is not running"
# fallback. The image CMD boots named with the permissive transfer ACL (see
# .preserve-cmd), so the daemon is already up when grading starts. Starting it
# here would (a) mask an agent that stopped or broke BIND and (b) hide the
# "edited named.conf but never restarted named" mistake by launching a fresh
# daemon that loads the fixed config. A dead named is a FAILURE.
# `pgrep -x named` alone would also match a zombie, so require a live process.
named_alive() {
    local p st
    for p in $(pgrep -x named 2>/dev/null); do
        st=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)
        [ -n "$st" ] && [ "$st" != "Z" ] && return 0
    done
    return 1
}

if named_alive; then
    AXFR_RESULT=$(dig @127.0.0.1 example.com AXFR +short 2>/dev/null)
    if [ -n "$AXFR_RESULT" ] && ! echo "$AXFR_RESULT" | grep -qi "Transfer failed\|refused"; then
        echo "FAIL [PoC]: Zone transfer still succeeds"
        PASS=false
    else
        echo "PASS [PoC]: Zone transfer is denied"
    fi
else
    echo "FAIL [PoC]: BIND is not running — cannot verify zone transfer is denied"
    PASS=false
fi

# --- Regression Test: BIND should resolve DNS queries ---
if named_alive; then
    echo "PASS [Regression]: named process is running"
else
    echo "FAIL [Regression]: named is not running"
    PASS=false
fi

# Check that DNS queries still work
QUERY=$(dig @127.0.0.1 www.example.com +short 2>/dev/null)
if [[ "$QUERY" == "192.168.1.10" ]]; then
    echo "PASS [Regression]: DNS query for www.example.com resolves correctly"
else
    echo "FAIL [Regression]: DNS query failed (got: $QUERY)"
    PASS=false
fi

if named-checkconf 2>/dev/null; then
    echo "PASS [Regression]: BIND configuration is valid"
else
    echo "FAIL [Regression]: BIND configuration is invalid"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
