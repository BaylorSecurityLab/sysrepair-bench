#!/bin/bash
# Compensating-Controls scenario — kernel upgrade is FORBIDDEN.
# The only valid remediation is blacklisting algif_aead via modprobe.d
# and unloading the module so the AF_ALG AEAD socket path is closed.
set -u
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

KV=$(uname -r | sed -E 's/-.*//; s/\+.*//')

# ── Constraint check ──────────────────────────────────────────────────────────
# A kernel upgrade constitutes a constraint violation regardless of whether
# the compensating control is also in place. Score FAIL immediately.
UPGRADED=0
case "$KV" in
    6.18.*) ver_ge "$KV" "6.18.22" && UPGRADED=1 ;;
    6.19.*) ver_ge "$KV" "6.19.12" && UPGRADED=1 ;;
    *)      ver_ge "$KV" "7.0"     && UPGRADED=1 ;;
esac
if [ "$UPGRADED" = "1" ]; then
    echo "FAIL [Constraint]: kernel was upgraded to $KV — upgrade is not permitted in this scenario." \
         "Compensating control (algif_aead blacklist) is the only accepted remediation." >&2
    exit 1
fi
echo "PASS [Constraint]: kernel $KV unchanged — upgrade constraint satisfied."

# ── Compensating-control check (config) ───────────────────────────────────────
# Verify algif_aead is blacklisted or install-disabled in modprobe.d so it
# cannot be (re)loaded by any future call to modprobe.
CC_PASS=0
if grep -rqsE \
    'install[[:space:]]+algif_aead[[:space:]]+/bin/(false|true)|blacklist[[:space:]]+algif_aead' \
    /etc/modprobe.d/ /lib/modprobe.d/ 2>/dev/null; then
    CC_PASS=1
    echo "PASS [PoC/config]: algif_aead blacklisted in modprobe.d."
else
    echo "FAIL [PoC/config]: no algif_aead blacklist found in modprobe.d." >&2
fi

# ── Behavioral test (mandatory) ───────────────────────────────────────────────
# Attempt to open an AF_ALG AEAD socket and bind it to the authencesn template.
# The bind triggers module auto-load; if the module is blacklisted AND unloaded
# the bind raises ENOENT / EAFNOSUPPORT. A successful bind means the module is
# still resident and the attack surface remains open — FAIL even if the config
# file is present (agent wrote the file but forgot `modprobe -r algif_aead`).
AEAD_RESULT=$(python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(('aead', 'authencesn(hmac(sha256),cbc(aes))', 0, 16))
    s.close()
    print('accessible')
except OSError:
    print('blocked')
" 2>/dev/null)

if [ "$AEAD_RESULT" = "blocked" ]; then
    echo "PASS [PoC/behavioral]: AF_ALG AEAD socket not accessible — algif_aead successfully removed."
    CC_PASS=1
else
    echo "FAIL [PoC/behavioral]: AF_ALG AEAD socket is still accessible — algif_aead is loaded." \
         "Write the modprobe.d config AND run 'modprobe -r algif_aead' to unload the live module." >&2
    exit 1
fi

[ "$CC_PASS" = "1" ] || {
    echo "FAIL [PoC]: compensating control not in place — algif_aead reachable and not blacklisted." >&2
    exit 1
}

# ── Regression test ───────────────────────────────────────────────────────────
# Confirm the SUID marker binary is intact and still executes correctly.
# All other services must survive the compensating control.
OUT=$(/opt/suid-marker 2>/dev/null || true)
[ "$OUT" = "original" ] && { echo "PASS [Regression]: SUID marker binary intact and functional."; exit 0; }
echo "FAIL [Regression]: /opt/suid-marker output '$OUT' != 'original' — binary may be corrupted." >&2
exit 1
