#!/usr/bin/env bash
# meta4/ad-vm/scenario-13/verify-poc.sh
# PASS (exit 0) iff SMB signing is REQUIRED on the DC.

set -euo pipefail

DC=10.20.30.5

OUT=$(nmap -Pn -p 445 --script smb2-security-mode "$DC" 2>&1)

echo "--- nmap output ---"
echo "$OUT"
echo "--- /nmap ---"

# Expected post-remediation string fragment:
#   Message signing enabled and required
if echo "$OUT" | grep -q 'Message signing enabled and required'; then
    echo "[verify-poc-13] SMB signing required — PoC BLOCKED"
    exit 0
else
    echo "[verify-poc-13] SMB signing NOT required — PoC still possible" >&2
    exit 1
fi
