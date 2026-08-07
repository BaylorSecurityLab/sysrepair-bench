#!/bin/bash
###############################################################################
# Scenario 17 - Verification Script
# BIND DNS zone transfer unrestricted
#
# PoC checks:        allow-transfer is not 'any' AND a real AXFR is refused
# Regression checks: named is alive, resolves queries, and its config is valid
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "closed the vulnerability but killed named" is reported as
# security_pass=true / regression_pass=false rather than collapsing into a bare
# exit 1. See lib/verifylib.sh.
###############################################################################

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC check: Zone transfers should be restricted ---
# Check named.conf.options for allow-transfer
TRANSFER=$(grep -rE 'allow-transfer' /etc/bind/named.conf.options /etc/bind/named.conf.local 2>/dev/null | grep -v '#')
if echo "$TRANSFER" | grep -q 'any'; then
    record_poc allow_transfer_restricted 0 "allow-transfer is set to 'any'"
else
    record_poc allow_transfer_restricted 1
fi

# NOTE: this verifier deliberately has NO "start named if it is not running"
# fallback. The image CMD boots named with the permissive transfer ACL (see
# .preserve-cmd), so the daemon is already up when grading starts. Starting it
# here would (a) mask an agent that stopped or broke BIND and (b) hide the
# "edited named.conf but never restarted named" mistake by launching a fresh
# daemon that loads the fixed config. A dead named is a FAILURE - it is recorded
# as the regression failure it is, and the AXFR probe then stays unmeasured
# rather than being scored as if it had run.
# `pgrep -x named` alone would also match a zombie, so require a live process.
named_alive() {
    local p st
    for p in $(pgrep -x named 2>/dev/null); do
        st=$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)
        [ -n "$st" ] && [ "$st" != "Z" ] && return 0
    done
    return 1
}

# --- Regression check: named must still be running ---
NAMED_UP=0
if named_alive; then
    NAMED_UP=1
    record_reg named_running 1
else
    record_reg named_running 0 "named is not running"
fi

# --- PoC behavioural check: Zone transfer MUST be denied (mandatory) ---
if [ "$NAMED_UP" -eq 0 ]; then
    echo "  [SKIP] BIND is not running - the AXFR probe cannot be measured"
else
    AXFR_RESULT=$(dig @127.0.0.1 example.com AXFR +short 2>/dev/null)
    if [ -n "$AXFR_RESULT" ] && ! echo "$AXFR_RESULT" | grep -qi "Transfer failed\|refused"; then
        record_poc zone_transfer_denied 0 "zone transfer still succeeds"
    else
        record_poc zone_transfer_denied 1
    fi
fi

# --- Regression check: BIND should still resolve DNS queries ---
QUERY=$(dig @127.0.0.1 www.example.com +short 2>/dev/null)
if [[ "$QUERY" == "192.168.1.10" ]]; then
    record_reg dns_query_resolves 1
else
    record_reg dns_query_resolves 0 "DNS query failed (got: $QUERY)"
fi

# --- Regression check: BIND configuration must still be valid ---
if named-checkconf 2>/dev/null; then
    record_reg bind_config_valid 1
else
    record_reg bind_config_valid 0 "BIND configuration is invalid"
fi

verify_finish
