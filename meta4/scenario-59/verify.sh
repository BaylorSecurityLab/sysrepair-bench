#!/bin/sh
# Scenario 59: Unbound - Open Recursive Resolver + version disclosure (misconfig)
#
# BEHAVIOURAL: the honest fix refuses everything except loopback and hides the
# software version. Because the fix ALLOWS localhost, a loopback probe can never
# show REFUSED - so we probe the container's NON-loopback (eth0) address: a query
# to eth0 must return REFUSED after the fix (baseline: NOERROR/answered). And
# version.bind CH TXT must no longer disclose the Unbound version. local.test
# must stay resolvable from localhost.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "closed the open resolver but killed unbound" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# unbound is booted by the image CMD (see .preserve-cmd). verify.sh must NEVER
# start it: a fresh start would mask "edited config but never restarted", and a
# dead daemon is a genuine failure. (No pgrep/pkill in this image - use pidof.)
UNBOUND_UP=0
if pidof unbound >/dev/null 2>&1; then
    UNBOUND_UP=1
    record_reg unbound_running 1
else
    record_reg unbound_running 0 \
        "unbound is not running - a dead service is a failure (verify.sh must not start it)"
fi

# Derive the container's non-loopback eth0 address (several fallbacks).
EIP=$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)
[ -z "$EIP" ] && EIP=$(hostname -i 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' | head -n1 || true)
[ -z "$EIP" ] && EIP=$(ip route get 1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' || true)

###############################################################################
# PoC 1 (behavioural): a query to the eth0 address must be REFUSED by access-control.
# Uses local.test so the probe is hermetic - no internet needed.
# PoC 2 (behavioural): version.bind must not disclose the Unbound version.
#
# Both are gated on unbound being alive: a dead resolver answers neither probe,
# and "no answer" must never be credited as "closed / version hidden".
###############################################################################
if [ -z "$EIP" ]; then
    # No probe source address, so the ACL probe measured nothing. Recorded as an
    # environment/regression failure with that PoC left UNRECORDED.
    record_reg probe_source_address 0 "could not determine a non-loopback address to probe"
elif [ "$UNBOUND_UP" -eq 1 ]; then
    PROBE=$(dig @"$EIP" local.test A +time=3 +tries=1 2>/dev/null || true)
    if echo "$PROBE" | grep -q 'status: REFUSED'; then
        record_poc query_refused_off_loopback 1 \
            "query to $EIP returns REFUSED (open resolver closed to loopback only)"
    else
        record_poc query_refused_off_loopback 0 \
            "query to $EIP is NOT refused - still an open resolver ($(echo "$PROBE" | grep -E 'status:|no servers' | head -1))"
    fi
else
    echo "  [SKIP] (poc) query_refused_off_loopback: unbound is not running"
fi

if [ "$UNBOUND_UP" -eq 1 ]; then
    VER_BIND=$(dig +short @127.0.0.1 version.bind CH TXT 2>/dev/null || true)
    if echo "$VER_BIND" | grep -qi 'unbound'; then
        record_poc version_bind_not_disclosed 0 \
            "version.bind discloses the Unbound version - hide-version not effective: $VER_BIND"
    else
        record_poc version_bind_not_disclosed 1
    fi
else
    echo "  [SKIP] (poc) version_bind_not_disclosed: unbound is not running"
fi

###############################################################################
# Config check (secondary): no 0.0.0.0/0 or ::/0 'allow', and hide-* not 'no'.
# Anchored to the drop-in dir to avoid grep -r path contamination.
###############################################################################
if grep -rhE 'access-control:[[:space:]]*(0\.0\.0\.0/0|::/0)[[:space:]]+allow' /etc/unbound/ 2>/dev/null | grep -q .; then
    record_poc access_control_hardened 0 "access-control still permits 0.0.0.0/0 or ::/0 allow"
else
    record_poc access_control_hardened 1
fi
if grep -rhE 'hide-(identity|version):[[:space:]]*no' /etc/unbound/ 2>/dev/null | grep -q .; then
    record_poc version_hiding_configured 0 "hide-identity or hide-version is still set to 'no'"
else
    record_poc version_hiding_configured 1
fi

###############################################################################
# Regression: local zone must still resolve from localhost.
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
    record_reg local_test_resolves 1 "local.test resolves to 10.0.0.1 from localhost"
else
    record_reg local_test_resolves 0 "local.test not resolving from localhost"
fi

verify_finish
