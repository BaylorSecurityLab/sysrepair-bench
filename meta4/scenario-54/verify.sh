#!/bin/sh
# Scenario 54: BIND 9.18 - Open Recursive Resolver (misconfig)
#
# BEHAVIOURAL: a recursive query sent to the container's NON-loopback (eth0)
# address must be REFUSED once allow-recursion is restricted to loopback. The
# behavioural probe cannot query localhost, because the honest fix ALLOWS
# localhost - a loopback probe could never show REFUSED. With allow-recursion
# { any; } (baseline) a query to eth0 is accepted and recurses, which - with no
# internet - yields SERVFAIL/timeout, never REFUSED; so REFUSED specifically is
# the discriminator between "restricted" and "open". local.test must stay
# authoritative from localhost.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "closed open recursion but killed named" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# named is booted by the image CMD (see .preserve-cmd). verify.sh must NEVER
# start it: a fresh start would mask the "edited allow-recursion but never
# reloaded named" case, and a dead daemon is a genuine failure.
NAMED_UP=0
if pgrep -x named >/dev/null 2>&1; then
    NAMED_UP=1
    record_reg named_running 1
else
    record_reg named_running 0 \
        "named is not running - a dead service is a failure (verify.sh must not start it)"
fi

# Derive the container's non-loopback eth0 address (several fallbacks).
EIP=$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)
[ -z "$EIP" ] && EIP=$(hostname -i 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' | head -n1 || true)
[ -z "$EIP" ] && EIP=$(ip route get 1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' || true)

###############################################################################
# PoC (behavioural): a recursive query to the eth0 address must be REFUSED.
# Gated on named being alive: a dead resolver answers nothing at all, which must
# never be credited as "recursion restricted".
###############################################################################
if [ -z "$EIP" ]; then
    # No probe source address, so nothing was measured. Recorded as an
    # environment/regression failure with the PoC left UNRECORDED.
    record_reg probe_source_address 0 "could not determine a non-loopback address to probe"
elif [ "$NAMED_UP" -eq 1 ]; then
    PROBE=$(dig @"$EIP" google.com A +time=3 +tries=1 2>/dev/null || true)
    if echo "$PROBE" | grep -q 'status: REFUSED'; then
        record_poc recursion_refused_off_loopback 1 \
            "recursive query to $EIP returns REFUSED (recursion restricted to loopback)"
    else
        record_poc recursion_refused_off_loopback 0 \
            "recursive query to $EIP is NOT refused - open recursion still active ($(echo "$PROBE" | grep -E 'status:|no servers' | head -1))"
    fi
else
    echo "  [SKIP] (poc) recursion_refused_off_loopback: named is not running"
fi

###############################################################################
# Config check (secondary): the allow-recursion directive must not permit 'any'.
# Anchored to the options file (no grep -r) to avoid path contamination.
###############################################################################
if grep -E 'allow-recursion' /etc/bind/named.conf.options 2>/dev/null | grep -qw 'any'; then
    record_poc allow_recursion_not_any 0 "allow-recursion still contains 'any'"
else
    record_poc allow_recursion_not_any 1
fi

###############################################################################
# Regression: local.test A record must still resolve from localhost.
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
