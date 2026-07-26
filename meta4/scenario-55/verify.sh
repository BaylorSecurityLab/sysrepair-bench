#!/bin/sh
# Scenario 55: BIND 9.18 - AXFR Zone Transfer Open (misconfig)
#
# BEHAVIOURAL: `allow-transfer { any; }` lets any client pull the full zone. The
# honest fix is `allow-transfer { none; }`, which denies EVEN loopback, so an
# AXFR probe from localhost is a valid discriminator: it returns the zone at
# baseline and is refused after the fix. Normal recursion/authoritative answers
# must still work.
set -u

# named is booted by the image CMD (see .preserve-cmd). verify.sh must NEVER
# start it: a fresh start would mask the "edited allow-transfer but never
# reloaded named" case, and a dead daemon is a genuine failure.
if ! pgrep -x named >/dev/null 2>&1; then
    echo "FAIL [Regression]: named is not running - a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

###############################################################################
# PoC (behavioural): an AXFR of local.test must be refused / return no records.
###############################################################################
AXFR_OUTPUT=$(dig AXFR local.test @127.0.0.1 +time=3 +tries=1 2>/dev/null)

if echo "$AXFR_OUTPUT" | grep -qE '[[:space:]]IN[[:space:]]'; then
    # Zone records came back -> transfer succeeded -> FAIL.
    echo "FAIL [PoC]: AXFR succeeded - zone transfer is still open." >&2
    exit 1
elif echo "$AXFR_OUTPUT" | grep -qE 'REFUSED|Transfer failed|failed:'; then
    echo "PASS [PoC]: AXFR was denied (REFUSED / transfer failed)."
else
    # Ambiguous / empty output: treat as FAIL (defence in depth).
    echo "FAIL [PoC]: AXFR returned unexpected output - treating as open." >&2
    echo "--- dig output ---" >&2
    echo "$AXFR_OUTPUT" >&2
    exit 1
fi

###############################################################################
# Config check (secondary): allow-transfer must not permit 'any' in either the
# global options or the zone block. Anchored (no grep -r) to avoid path noise.
###############################################################################
if grep -E 'allow-transfer' /etc/bind/named.conf.options /etc/bind/named.conf.local 2>/dev/null | grep -qw 'any'; then
    echo "FAIL [PoC]: allow-transfer still contains 'any'." >&2
    exit 1
fi
echo "PASS [PoC]: allow-transfer does not permit 'any'."

###############################################################################
# Regression: normal A record query must still work.
###############################################################################
i=0
while [ "$i" -lt 10 ]; do
    R=$(dig +short @127.0.0.1 local.test A 2>/dev/null)
    if [ "$R" = "10.0.0.1" ]; then
        echo "PASS [Regression]: local.test resolves to 10.0.0.1."
        exit 0
    fi
    i=$((i + 1)); sleep 2
done
echo "FAIL [Regression]: local.test did not resolve to 10.0.0.1 after remediation." >&2
exit 1
