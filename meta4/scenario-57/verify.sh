#!/bin/sh
# Scenario 57: CoreDNS 1.11.1 - No ACL / open resolver (misconfig)
#
# BEHAVIOURAL: with no acl plugin, CoreDNS answers/forwards for any source. The
# honest fix adds `acl { allow net 127.0.0.0/8; block }` so only loopback is
# served. Because the fix ALLOWS localhost, a loopback probe can never show
# REFUSED - so we probe the container's NON-loopback (eth0) address instead: a
# query to eth0 must return REFUSED after the fix (baseline: NOERROR/answered).
# local.test must stay resolvable from localhost.
set -u

# CoreDNS is booted by the image CMD (see .preserve-cmd). verify.sh must NEVER
# start it: a fresh start would mask "edited Corefile but never restarted", and a
# dead daemon is a genuine failure.
if ! pgrep coredns >/dev/null 2>&1; then
    echo "FAIL [Regression]: coredns is not running - a dead service is a failure" >&2
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
# PoC (behavioural): a query to the eth0 address must be REFUSED by the ACL.
# Uses local.test (authoritative) so the probe is hermetic - no internet needed.
###############################################################################
PROBE=$(dig @"$EIP" local.test A +time=3 +tries=1 2>/dev/null)
if echo "$PROBE" | grep -q 'status: REFUSED'; then
    echo "PASS [PoC]: query to $EIP returns REFUSED (ACL restricts to loopback)."
else
    echo "FAIL [PoC]: query to $EIP is NOT refused - no effective ACL (open resolver)." >&2
    echo "$PROBE" | grep -E 'status:|no servers' >&2
    exit 1
fi

###############################################################################
# Config check (secondary): the Corefile must contain an acl block.
###############################################################################
if ! grep -qE '^[[:space:]]*acl[[:space:]]*\{?' /Corefile 2>/dev/null; then
    echo "FAIL [PoC]: Corefile does not contain an 'acl' block." >&2
    exit 1
fi
echo "PASS [PoC]: Corefile contains an 'acl' block."

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
