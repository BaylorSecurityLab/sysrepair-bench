#!/bin/bash
# CVE-2024-50379 — Tomcat case-insensitive JSP upload race. The exploitable
# precondition is the writable default servlet (readonly=false). Ground truth
# is BEHAVIORAL against the LIVE server on 8080: a PUT that lands a file proves
# the servlet is writable. Boots already-running (.preserve-cmd), so a config
# edit without a restart still serves the vulnerable config and FAILs here.
set -u
BASE=http://127.0.0.1:8080

UP=0
for i in $(seq 1 30); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 3 "$BASE/" 2>/dev/null)" = "200" ]; then UP=1; break; fi
    sleep 2
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: Tomcat did not serve HTTP 200 on 8080 (dead/not restarted)." >&2
    exit 1
fi

# --- dynamic probe: writable default servlet -------------------------------
PROBE="/verify_probe_$$.txt"
PUT_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X PUT --data-binary 'TEST' "$BASE$PROBE" 2>/dev/null || echo 000)
if [ "$PUT_CODE" = "201" ] || [ "$PUT_CODE" = "204" ] || [ "$PUT_CODE" = "200" ]; then
    GET_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$BASE$PROBE" 2>/dev/null || echo 000)
    curl -s -o /dev/null -m 5 -X DELETE "$BASE$PROBE" 2>/dev/null || true
    echo "FAIL [PoC]: PUT accepted (HTTP $PUT_CODE, GET $GET_CODE) — default servlet writable (readonly=false live)." >&2
    exit 1
fi
echo "PASS [PoC]: PUT rejected (HTTP $PUT_CODE) — default servlet read-only / patched."

if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 3 "$BASE/" 2>/dev/null)" = "200" ]; then
    echo "PASS [Regression]: Tomcat HTTP 8080 reachable (HTTP 200)."
    exit 0
fi
echo "FAIL [Regression]: Tomcat HTTP 8080 not serving 200 after probe." >&2
exit 1
