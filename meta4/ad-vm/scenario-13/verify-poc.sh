#!/usr/bin/env bash
# meta4/ad-vm/scenario-13/verify-poc.sh
# PASS (exit 0) iff SMB signing is REQUIRED on corp-ws01.
#
# RETARGETED from the DC (10.20.30.5) to corp-ws01 (10.20.30.20).
#
# Two reasons, both making the scenario sounder rather than merely different:
#
#  1. A member server is the realistic NTLM-relay target. Domain controllers
#     require SMB signing by DEFAULT, and that default is enforced by the
#     Default Domain Controllers Policy -- so the inject was fighting a GPO
#     that reasserts itself on the next refresh, and the vulnerable state it
#     created had a shelf life. Member machines do not require signing by
#     default, which is exactly why relaying to them works.
#
#  2. It is genuinely vulnerable there. Confirmed on the live lab: netexec
#     reports corp-ws01 as "(signing:False)".
#
# It also FAILS CLOSED properly now. The previous version was a bare if/else on
# a single nmap string, so an unreachable host, a missing nmap, or an nmap error
# all landed in the else branch and reported "SMB signing NOT required" --
# indistinguishable from a real finding. For a security verdict that is the safe
# direction, but it is still an unreachable host masquerading as evidence, and
# it would equally have hidden a broken probe during gate 2.

set -uo pipefail

TARGET=10.20.30.20

if ! command -v nmap >/dev/null 2>&1; then
    echo "[verify-poc-13] HARNESS ERROR: nmap not present on the attacker" >&2
    exit 2
fi

OUT=$(timeout 60 nmap -Pn -p 445 --script smb2-security-mode "$TARGET" 2>&1)
RC=$?

echo "--- nmap output (rc=$RC) ---"
echo "$OUT"
echo "--- /nmap ---"

if [ "$RC" -eq 124 ]; then
    echo "[verify-poc-13] HARNESS ERROR: nmap timed out after 60s" >&2
    exit 2
fi

# --- host not answering on 445: HARNESS ERROR, never a verdict ---
# A closed or filtered port says nothing about the signing policy of the
# service behind it.
if echo "$OUT" | grep -qiE '445/tcp[[:space:]]+(closed|filtered)|Host seems down|0 hosts up'; then
    echo "[verify-poc-13] HARNESS ERROR: $TARGET is not answering on 445" >&2
    echo "[verify-poc-13] an unreachable SMB service is not evidence of remediation" >&2
    exit 2
fi

# --- the script must actually have produced a signing verdict ---
if ! echo "$OUT" | grep -qi 'Message signing'; then
    echo "[verify-poc-13] HARNESS ERROR: smb2-security-mode returned no signing verdict" >&2
    echo "[verify-poc-13] nothing can be concluded from a silent script" >&2
    exit 2
fi

# --- signing required: relay blocked ---
if echo "$OUT" | grep -q 'Message signing enabled and required'; then
    echo "[verify-poc-13] SMB signing required on $TARGET -- PoC BLOCKED"
    exit 0
fi

echo "[verify-poc-13] SMB signing NOT required on $TARGET -- NTLM relay still possible" >&2
exit 1
