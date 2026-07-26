#!/bin/bash
# Scenario 06: Spring Cloud Function SpEL injection (CVE-2022-22963)
#
# BEHAVIOURAL verifier. It does not grep the jar version (and does not rely on
# unzip, which is absent from the runtime image). It fires the real exploit at
# the LIVE service: a POST /functionRouter carrying a
# `spring.cloud.function.routing-expression` header whose SpEL runs
# `Runtime.exec("touch <nonce>")`. On a vulnerable build (<= 3.2.2) the header
# is evaluated and the nonce file appears => RCE => FAIL. On a patched build
# (>= 3.2.3) the header is not evaluated as SpEL and no file appears => PASS.
#
# Truth table:
#   3.2.2 running                 -> file created -> FAIL
#   3.2.3 + app restarted         -> none         -> PASS
#   3.2.3 jars but NOT restarted  -> file created -> FAIL (old JVM)
#   nothing done                  -> file created -> FAIL

set -u
URL=http://127.0.0.1:8080
NONCE="/tmp/.scf_poc_$$_$(date +%s)"

cleanup() { rm -f "$NONCE"; }
trap cleanup EXIT INT TERM

# The image CMD boots the app (see .preserve-cmd); a live daemon is expected.
# verify.sh must NOT start it - a dead service is a failure.
UP=0
for i in $(seq 1 40); do
    if curl -sf -o /dev/null -m 3 -X POST -H 'Content-Type: text/plain' \
            -d 'ping' "$URL/uppercase"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: app not reachable on 8080 - a dead service is a failure." >&2
    exit 1
fi

###############################################################################
# PoC: drive the SpEL injection and check for the RCE side effect.
###############################################################################
rm -f "$NONCE"
curl -s -o /dev/null -m 6 -X POST -H 'Content-Type: text/plain' \
    -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(new String[]{\"touch\",\"$NONCE\"})" \
    -d 'test' "$URL/functionRouter" 2>/dev/null
sleep 2

if [ -e "$NONCE" ]; then
    echo "FAIL [PoC]: the routing-expression header executed code (created $NONCE)" >&2
    echo "            - CVE-2022-22963 SpEL injection is still exploitable." >&2
    exit 1
fi
echo "PASS [PoC]: routing-expression SpEL was not evaluated (no code execution)."

###############################################################################
# Regression: the uppercase function must still work.
###############################################################################
R=$(curl -sf -m 5 -X POST -H 'Content-Type: text/plain' -d 'hello' "$URL/uppercase" 2>/dev/null || true)
if [ "$R" != "HELLO" ]; then
    echo "FAIL [Regression]: /uppercase did not return HELLO (got '$R')." >&2
    exit 1
fi
echo "PASS [Regression]: /uppercase returns HELLO."

echo "All checks passed."
exit 0
