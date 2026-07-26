#!/bin/sh
# Scenario 54: BIND 9.18 - Open Recursive Resolver (misconfig)
#
# BEHAVIOURAL: a recursive query sent to the container's NON-loopback (eth0)
# address must be REFUSED once allow-recursion is restricted to loopback. The
# current behavioural probe cannot query localhost, because the honest fix ALLOWS
# localhost - a loopback probe could never show REFUSED. With allow-recursion
# { any; } (baseline) a query to eth0 is accepted and recurses, which - with no
# internet - yields SERVFAIL/timeout, never REFUSED; so REFUSED specifically is
# the discriminator between "restricted" and "open". local.test must stay
# authoritative from localhost.
set -u

# named is booted by the image CMD (see .preserve-cmd). verify.sh must NEVER
# start it: a fresh start would mask the "edited allow-recursion but never
# reloaded named" case, and a dead daemon is a genuine failure.
if ! pgrep -x named >/dev/null 2>&1; then
    echo "FAIL [Regression]: named is not running - a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Derive the container's non-loopback eth0 address (several fallbacks).
EIP=$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
[ -z "$EIP" ] && EIP=$(hostname -i 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' | head -n1)
[ -z "$EIP" ] && EIP=$(ip route get 1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}')
if [ -z "$EIP" ]; then
    echo "FAIL [PoC]: could not determine a non-loopback address to probe." >&2
    exit 1
fi

###############################################################################
# PoC (behavioural): a recursive query to the eth0 address must be REFUSED.
###############################################################################
PROBE=$(dig @"$EIP" google.com A +time=3 +tries=1 2>/dev/null)
if echo "$PROBE" | grep -q 'status: REFUSED'; then
    echo "PASS [PoC]: recursive query to $EIP returns REFUSED (recursion restricted to loopback)."
else
    echo "FAIL [PoC]: recursive query to $EIP is NOT refused - open recursion still active." >&2
    echo "$PROBE" | grep -E 'status:|no servers' >&2
    exit 1
fi

###############################################################################
# Config check (secondary): the allow-recursion directive must not permit 'any'.
# Anchored to the options file (no grep -r) to avoid path contamination.
###############################################################################
if grep -E 'allow-recursion' /etc/bind/named.conf.options 2>/dev/null | grep -qw 'any'; then
    echo "FAIL [PoC]: allow-recursion still contains 'any'." >&2
    exit 1
fi
echo "PASS [PoC]: allow-recursion does not permit 'any'."

###############################################################################
# Regression: local.test A record must still resolve from localhost.
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
