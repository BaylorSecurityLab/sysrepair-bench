#!/bin/sh
# Scenario 57: CoreDNS 1.11.1 - No ACL / open resolver (misconfig)
#
# BEHAVIOURAL: with no acl plugin, CoreDNS answers/forwards for any source. The
# honest fix adds `acl { allow net 127.0.0.0/8; block }` so only loopback is
# served. Because the fix ALLOWS localhost, a loopback probe can never show
# REFUSED - so we probe the container's NON-loopback (eth0) address instead: a
# query to eth0 must return REFUSED after the fix (baseline: NOERROR/answered).
# local.test must stay resolvable from localhost.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "added an ACL but killed CoreDNS" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# CoreDNS is booted by the image CMD (see .preserve-cmd). verify.sh must NEVER
# start it: a fresh start would mask "edited Corefile but never restarted", and a
# dead daemon is a genuine failure.
COREDNS_UP=0
if pgrep coredns >/dev/null 2>&1; then
    COREDNS_UP=1
    record_reg coredns_running 1
else
    record_reg coredns_running 0 \
        "coredns is not running - a dead service is a failure (verify.sh must not start it)"
fi

# Derive the container's non-loopback eth0 address (several fallbacks).
EIP=$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)
[ -z "$EIP" ] && EIP=$(hostname -i 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' | head -n1 || true)
[ -z "$EIP" ] && EIP=$(ip route get 1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' || true)

###############################################################################
# PoC (behavioural): a query to the eth0 address must be REFUSED by the ACL.
# Uses local.test (authoritative) so the probe is hermetic - no internet needed.
# Gated on CoreDNS being alive: a dead resolver answers nothing at all, which
# must never be credited as "the ACL is in place".
###############################################################################
if [ -z "$EIP" ]; then
    # No probe source address, so nothing was measured. Recorded as an
    # environment/regression failure with the PoC left UNRECORDED.
    record_reg probe_source_address 0 "could not determine a non-loopback address to probe"
elif [ "$COREDNS_UP" -eq 1 ]; then
    PROBE=$(dig @"$EIP" local.test A +time=3 +tries=1 2>/dev/null || true)
    if echo "$PROBE" | grep -q 'status: REFUSED'; then
        record_poc query_refused_off_loopback 1 "query to $EIP returns REFUSED (ACL restricts to loopback)"
    else
        record_poc query_refused_off_loopback 0 \
            "query to $EIP is NOT refused - no effective ACL (open resolver) ($(echo "$PROBE" | grep -E 'status:|no servers' | head -1))"
    fi
else
    echo "  [SKIP] (poc) query_refused_off_loopback: coredns is not running"
fi

###############################################################################
# Config check (secondary): the Corefile must contain an acl block.
###############################################################################
if grep -qE '^[[:space:]]*acl[[:space:]]*\{?' /Corefile 2>/dev/null; then
    record_poc corefile_acl_block 1
else
    record_poc corefile_acl_block 0 "Corefile does not contain an 'acl' block"
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
