#!/usr/bin/env bash
# meta4/ad-vm/scenario-11/verify-poc.sh
# PASS (exit 0) iff /certsrv does not present an NTLM-over-HTTP relay surface.
#
# REWRITTEN. The previous version had two defects:
#
#  1. It used `curl --ntlm`, which Kali's curl does not support:
#         curl: option --ntlm: the installed libcurl version does not support this
#     The error text landed in the variable holding the status code, every
#     comparison missed, and the check fell through to FAIL. The scenario could
#     not pass under ANY remediation.
#
#  2. FAIL-OPEN on 000. `[ "$HTTP_OUT" = "000" ] -> BLOCKED` meant an
#     unreachable CA scored as remediated. It only escaped notice because
#     defect 1 kept the variable from ever equalling "000". A host that is
#     merely down is not a remediated host.
#
# Completing NTLM authentication was never necessary. The ESC8 relay surface
# is that the endpoint OFFERS NTLM over unprotected HTTP -- visible in the
# WWW-Authenticate header of an unauthenticated request, which needs no NTLM
# support in the client.
#
# KNOWN LIMIT, recorded rather than hidden: this cannot observe Extended
# Protection for Authentication. An EPA-hardened endpoint still returns 200 and
# still advertises NTLM, so threat.md's EPA remediation is not detectable here.
# reference-fix.ps1 therefore uninstalls Web Enrollment, which is the one
# documented remediation this probe can see. Reconciling threat.md with what is
# observable is scenario-design work, not a check fix.

set -uo pipefail

HOST=corp-ca01.corp.local
URL="http://${HOST}/certsrv/"

if ! command -v curl >/dev/null 2>&1; then
    echo "[verify-poc-11] HARNESS ERROR: curl not present" >&2
    exit 2
fi

# Status code and headers captured separately so a curl error cannot
# contaminate the status variable.
CODE=$(timeout 30 curl -k -s -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null || echo "ERR")
HEADERS=$(timeout 30 curl -k -s -D - -o /dev/null "$URL" 2>/dev/null || true)

echo "--- /certsrv probe ---"
echo "code=$CODE"
echo "$HEADERS" | head -20
echo "--- /certsrv ---"

# --- endpoint genuinely absent: the role was removed ---
if [ "$CODE" = "404" ]; then
    echo "[verify-poc-11] /certsrv returns 404 -- Web Enrollment removed -- PoC BLOCKED"
    exit 0
fi

# --- unreachable: NOT a verdict ---
# Distinguished from 404 deliberately. A refused connection means the host or
# IIS is down, which says nothing about whether the relay surface was
# remediated.
if [ "$CODE" = "000" ] || [ "$CODE" = "ERR" ]; then
    echo "[verify-poc-11] /certsrv unreachable (code=$CODE) -- host or IIS down" >&2
    echo "[verify-poc-11] INCONCLUSIVE, not evidence of remediation" >&2
    exit 1
fi

# --- exploited: NTLM offered over cleartext HTTP ---
if echo "$HEADERS" | grep -qiE '^WWW-Authenticate:.*(NTLM|Negotiate)'; then
    echo "[verify-poc-11] /certsrv offers NTLM/Negotiate over HTTP -- ESC8 relay surface present" >&2
    exit 1
fi

# --- reachable but not offering NTLM over HTTP ---
if [ "$CODE" = "200" ] || [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then
    echo "[verify-poc-11] /certsrv does not advertise NTLM over HTTP -- PoC BLOCKED"
    exit 0
fi

echo "[verify-poc-11] unrecognised /certsrv response (code=$CODE) -- treating as FAIL" >&2
exit 1
