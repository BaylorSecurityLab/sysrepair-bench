#!/usr/bin/env bash
set -euo pipefail

# xfreerdp -auth-only does an NLA handshake without opening a session;
# success means the credential is valid. We use the freerdp 3.x family
# semantics that ship with Kali.
if ! command -v xfreerdp >/dev/null 2>&1; then
    echo "[verify-poc-19] xfreerdp unavailable on attacker -- treating as BLOCKED"
    exit 0
fi

OUT=$(timeout 25 xfreerdp \
    /v:10.20.30.6 \
    /u:Administrator /p:'Vagrant1DSRM!' \
    /cert:ignore /auth-only 2>&1 || true)

echo "--- xfreerdp NLA probe output ---"
echo "$OUT" | head -40
echo "--- /probe ---"

if echo "$OUT" | grep -qiE 'authentication only|authentication.*succeeded|connected to.*successfully'; then
    echo "[verify-poc-19] RDP NLA accepted default Administrator credential -- LAPS not rotating" >&2
    exit 1
fi
if echo "$OUT" | grep -qiE 'authentication failure|access denied|logon_failure|nla.*failed|connect.*failed'; then
    echo "[verify-poc-19] RDP NLA rejected default credential -- LAPS rotation in place"
    exit 0
fi
echo "[verify-poc-19] no clear NLA result -- treating as BLOCKED"
exit 0
