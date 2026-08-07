#!/bin/sh
# Scenario 55: BIND 9.18 - AXFR Zone Transfer Open (misconfig)
#
# BEHAVIOURAL: `allow-transfer { any; }` lets any client pull the full zone. The
# honest fix is `allow-transfer { none; }`, which denies EVEN loopback, so an
# AXFR probe from localhost is a valid discriminator: it returns the zone at
# baseline and is refused after the fix. Normal recursion/authoritative answers
# must still work.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "closed AXFR but killed named" is reported as security_pass /
# regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# named is booted by the image CMD (see .preserve-cmd). verify.sh must NEVER
# start it: a fresh start would mask the "edited allow-transfer but never
# reloaded named" case, and a dead daemon is a genuine failure.
NAMED_UP=0
if pgrep -x named >/dev/null 2>&1; then
    NAMED_UP=1
    record_reg named_running 1
else
    record_reg named_running 0 \
        "named is not running - a dead service is a failure (verify.sh must not start it)"
fi

###############################################################################
# PoC (behavioural): an AXFR of local.test must be refused / return no records.
# Gated on named being alive: a dead server also makes the transfer "fail",
# which must never be credited as "zone transfer closed".
###############################################################################
if [ "$NAMED_UP" -eq 1 ]; then
    AXFR_OUTPUT=$(dig AXFR local.test @127.0.0.1 +time=3 +tries=1 2>/dev/null || true)

    if echo "$AXFR_OUTPUT" | grep -qE '[[:space:]]IN[[:space:]]'; then
        # Zone records came back -> transfer succeeded -> FAIL.
        record_poc axfr_denied 0 "AXFR succeeded - zone transfer is still open"
    elif echo "$AXFR_OUTPUT" | grep -qE 'REFUSED|Transfer failed|failed:'; then
        record_poc axfr_denied 1 "AXFR was denied (REFUSED / transfer failed)"
    else
        # Ambiguous / empty output: treat as FAIL (defence in depth).
        record_poc axfr_denied 0 "AXFR returned unexpected output - treating as open: $AXFR_OUTPUT"
    fi
else
    echo "  [SKIP] (poc) axfr_denied: named is not running"
fi

###############################################################################
# Config check (secondary): allow-transfer must not permit 'any' in either the
# global options or the zone block. Anchored (no grep -r) to avoid path noise.
###############################################################################
if grep -E 'allow-transfer' /etc/bind/named.conf.options /etc/bind/named.conf.local 2>/dev/null | grep -qw 'any'; then
    record_poc allow_transfer_not_any 0 "allow-transfer still contains 'any'"
else
    record_poc allow_transfer_not_any 1
fi

###############################################################################
# Regression: normal A record query must still work.
###############################################################################
i=0
RESOLVED=0
while [ "$i" -lt 10 ]; do
    R=$(dig +short @127.0.0.1 local.test A 2>/dev/null || true)
    if [ "$R" = "10.0.0.1" ]; then
        RESOLVED=1
        break
    fi
    i=$((i + 1)); sleep 2
done
if [ "$RESOLVED" -eq 1 ]; then
    record_reg local_test_resolves 1 "local.test resolves to 10.0.0.1"
else
    record_reg local_test_resolves 0 "local.test did not resolve to 10.0.0.1"
fi

verify_finish
