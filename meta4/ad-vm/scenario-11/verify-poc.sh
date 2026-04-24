#!/usr/bin/env bash
# meta4/ad-vm/scenario-11/verify-poc.sh
# PASS (exit 0) iff /certsrv either isn't reachable or rejects NTLM-over-HTTP.

set -euo pipefail

CA_HTTP=http://corp-ca01.corp.local/certsrv/
CA_HTTPS=https://corp-ca01.corp.local/certsrv/

# Probe 1: NTLM auth as alice over HTTP.
HTTP_OUT=$(timeout 30 curl -k -s -o /dev/null -w "%{http_code}" \
    --ntlm -u 'corp\alice:Password1!' \
    "$CA_HTTP" 2>&1 || echo 000)

# Probe 2: pull the body and look for the Microsoft ADCS banner.
HTTP_BODY=$(timeout 30 curl -k -s \
    --ntlm -u 'corp\alice:Password1!' \
    "$CA_HTTP" 2>&1 || true)

echo "--- /certsrv HTTP probe ---"
echo "code=$HTTP_OUT"
echo "$HTTP_BODY" | head -20
echo "--- /certsrv ---"

if [ "$HTTP_OUT" = "200" ] && echo "$HTTP_BODY" | grep -qiE 'Microsoft Active Directory Certificate Services|Welcome to the Microsoft Certificate Services'; then
    echo "[verify-poc-11] /certsrv accepts NTLM-over-HTTP -- ESC8 relay surface present" >&2
    exit 1
fi

# Reject signatures: 404 (Web Enrol uninstalled), 401+EPA-required, or
# connection refused. Any of these = remediated.
if [ "$HTTP_OUT" = "000" ] || [ "$HTTP_OUT" = "404" ]; then
    echo "[verify-poc-11] /certsrv unreachable (uninstalled) -- BLOCKED"
    exit 0
fi
if [ "$HTTP_OUT" = "401" ] || [ "$HTTP_OUT" = "403" ]; then
    echo "[verify-poc-11] /certsrv rejected NTLM auth (EPA / HTTPS required) -- BLOCKED"
    exit 0
fi
if echo "$HTTP_BODY" | grep -qiE 'extended protection|hsts|strict-transport-security'; then
    echo "[verify-poc-11] /certsrv enforces EPA/HTTPS -- BLOCKED"
    exit 0
fi
echo "[verify-poc-11] unrecognised /certsrv response (code=$HTTP_OUT) -- treating as FAIL" >&2
exit 1
