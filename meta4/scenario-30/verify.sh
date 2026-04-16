#!/bin/bash
set -u
BASE=http://127.0.0.1:5000

# PoC 1: VULNERABLE must be 0
if [ "${VULNERABLE:-1}" != "0" ]; then
    echo "FAIL [PoC]: VULNERABLE env is '${VULNERABLE:-unset}' (need 0)." >&2
    exit 1
fi
echo "PASS [PoC]: VULNERABLE=0 (secure mode)."

# PoC 2: SECRET_KEY must not be the default
SK="${SECRET_KEY:-}"
case "$SK" in
    ""|secret|changeme|default|password|test) echo "FAIL [PoC]: weak SECRET_KEY '$SK'." >&2; exit 1 ;;
esac
if [ "${#SK}" -lt 16 ]; then
    echo "FAIL [PoC]: SECRET_KEY too short (${#SK} chars, need >= 16)." >&2
    exit 1
fi
echo "PASS [PoC]: SECRET_KEY is non-default and >= 16 chars."

# Regression
for i in $(seq 1 20); do
    curl -sf -o /dev/null -m 2 "$BASE/" && { echo "PASS [Regression]: VAmPI reachable on 5000."; exit 0; }
    sleep 1
done
echo "FAIL [Regression]: VAmPI unreachable on 5000." >&2
exit 1
