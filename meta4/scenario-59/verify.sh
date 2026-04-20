#!/bin/bash
# Scenario 59: Unbound — Open Recursive Resolver (DNS Amplification)
set -u

###############################################################################
# PoC 1: Recursive queries from 0.0.0.0/0 must be refused
###############################################################################

if grep -rq 'access-control:.*0\.0\.0\.0/0.*allow' /etc/unbound/ 2>/dev/null; then
    echo "FAIL [PoC]: access-control still permits 0.0.0.0/0 allow." >&2
    exit 1
fi
echo "PASS [PoC]: No 0.0.0.0/0 allow in access-control."

if grep -rq 'access-control:.*::/0.*allow' /etc/unbound/ 2>/dev/null; then
    echo "FAIL [PoC]: access-control still permits ::/0 allow." >&2
    exit 1
fi
echo "PASS [PoC]: No ::/0 allow in access-control."

###############################################################################
# PoC 2: Version disclosure must be suppressed
###############################################################################

if grep -rq 'hide-identity:.*no\|hide-version:.*no' /etc/unbound/ 2>/dev/null; then
    echo "FAIL [PoC]: hide-identity or hide-version still set to no." >&2
    exit 1
fi
echo "PASS [PoC]: Version disclosure suppressed."

# PoC (behavioral): verify version.bind query is suppressed
VER_BIND=$(dig +short @127.0.0.1 version.bind CH TXT 2>/dev/null || true)
if echo "$VER_BIND" | grep -qi 'unbound'; then
    echo "FAIL [PoC]: version.bind query returns Unbound version — hide-version not effective." >&2
    exit 1
fi
echo "PASS [PoC]: version.bind query does not disclose Unbound version."

###############################################################################
# Regression: Local zone must still resolve from localhost
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    RESULT=$(dig +short @127.0.0.1 local.test A 2>/dev/null)
    if [ "$RESULT" = "10.0.0.1" ]; then
        echo "PASS [Regression]: local.test resolves to 10.0.0.1 from localhost."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: local.test not resolving after remediation." >&2
exit 1
