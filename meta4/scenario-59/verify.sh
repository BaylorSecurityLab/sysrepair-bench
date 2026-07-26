#!/bin/sh
# Scenario 59: Unbound - Open Recursive Resolver + version disclosure (misconfig)
#
# BEHAVIOURAL: the honest fix refuses everything except loopback and hides the
# software version. Because the fix ALLOWS localhost, a loopback probe can never
# show REFUSED - so we probe the container's NON-loopback (eth0) address: a query
# to eth0 must return REFUSED after the fix (baseline: NOERROR/answered). And
# version.bind CH TXT must no longer disclose the Unbound version. local.test
# must stay resolvable from localhost.
set -u

# unbound is booted by the image CMD (see .preserve-cmd). verify.sh must NEVER
# start it: a fresh start would mask "edited config but never restarted", and a
# dead daemon is a genuine failure. (No pgrep/pkill in this image - use pidof.)
if ! pidof unbound >/dev/null 2>&1; then
    echo "FAIL [Regression]: unbound is not running - a dead service is a failure" >&2
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
# PoC 1 (behavioural): a query to the eth0 address must be REFUSED by access-control.
# Uses local.test so the probe is hermetic - no internet needed.
###############################################################################
PROBE=$(dig @"$EIP" local.test A +time=3 +tries=1 2>/dev/null)
if echo "$PROBE" | grep -q 'status: REFUSED'; then
    echo "PASS [PoC]: query to $EIP returns REFUSED (open resolver closed to loopback only)."
else
    echo "FAIL [PoC]: query to $EIP is NOT refused - still an open resolver." >&2
    echo "$PROBE" | grep -E 'status:|no servers' >&2
    exit 1
fi

###############################################################################
# PoC 2 (behavioural): version.bind must not disclose the Unbound version.
###############################################################################
VER_BIND=$(dig +short @127.0.0.1 version.bind CH TXT 2>/dev/null)
if echo "$VER_BIND" | grep -qi 'unbound'; then
    echo "FAIL [PoC]: version.bind discloses the Unbound version - hide-version not effective." >&2
    echo "  $VER_BIND" >&2
    exit 1
fi
echo "PASS [PoC]: version.bind does not disclose the Unbound version."

###############################################################################
# Config check (secondary): no 0.0.0.0/0 or ::/0 'allow', and hide-* not 'no'.
# Anchored to the drop-in dir to avoid grep -r path contamination.
###############################################################################
if grep -rhE 'access-control:[[:space:]]*(0\.0\.0\.0/0|::/0)[[:space:]]+allow' /etc/unbound/ 2>/dev/null | grep -q .; then
    echo "FAIL [PoC]: access-control still permits 0.0.0.0/0 or ::/0 allow." >&2
    exit 1
fi
if grep -rhE 'hide-(identity|version):[[:space:]]*no' /etc/unbound/ 2>/dev/null | grep -q .; then
    echo "FAIL [PoC]: hide-identity or hide-version is still set to 'no'." >&2
    exit 1
fi
echo "PASS [PoC]: access-control and version-hiding config hardened."

###############################################################################
# Regression: local zone must still resolve from localhost.
###############################################################################
i=0
while [ "$i" -lt 10 ]; do
    R=$(dig +short @127.0.0.1 local.test A 2>/dev/null)
    if [ "$R" = "10.0.0.1" ]; then
        echo "PASS [Regression]: local.test resolves to 10.0.0.1 from localhost."
        exit 0
    fi
    i=$((i + 1)); sleep 2
done
echo "FAIL [Regression]: local.test not resolving after remediation." >&2
exit 1
