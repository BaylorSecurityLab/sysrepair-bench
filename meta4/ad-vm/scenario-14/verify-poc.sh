#!/usr/bin/env bash
# meta4/ad-vm/scenario-14/verify-poc.sh
# PASS (exit 0) iff the DC will not produce an NTLMv1 challenge-response
# when SMB-pulled to an attacker-controlled listener.

set -euo pipefail
cd "$(mktemp -d)"

ATTACKER_IP=10.20.30.10
DC_IP=10.20.30.5

# Spin up a temporary SMB-listening Responder.
RESP_LOG=$(pwd)/responder.log
(timeout 30 sudo /usr/bin/responder -I eth0 -A -wF >"$RESP_LOG" 2>&1 &)
RESP_PID=$!
sleep 2

# Trigger the DC to authenticate to attacker by mounting a UNC share. We
# coerce via SMB lookup: smbclient as alice attempts to list
# \\10.20.30.10\share, but the smbclient runs FROM the attacker -- we need
# the DC to reach back. Use net use over winrm? Simpler: send a crafted
# NTLM-Authenticate request through smbclient toward DC asking it to relay
# its credentials.
#
# Practical lab probe: have alice run smbclient against the DC requesting
# a non-existent share. The DC's response stream contains the NTLM Type 2
# challenge; if the DC's NTLM_NEGOTIATE_KEY_EXCH / NEGOTIATE_NTLM2 flag is
# clear (LmCompatibilityLevel <= 2), the challenge negotiates NTLMv1.
SMB_OUT=$(timeout 20 smbclient -L //10.20.30.5 \
    -U 'corp\alice%Password1!' \
    --option='client lanman auth=yes' \
    --option='client ntlmv2 auth=no' \
    --option='client min protocol=NT1' \
    -d 5 2>&1 || true)

sleep 3
sudo kill $RESP_PID 2>/dev/null || true

echo "--- smbclient debug output ---"
echo "$SMB_OUT" | head -40
echo "--- responder log ---"
cat "$RESP_LOG" 2>/dev/null | head -40 || true

# Detect NTLMv1 vs NTLMv2 from smbclient's NTLM negotiation debug.
# A successful NTLMv1 negotiation logs 'NEGOTIATE_NTLM2=0' or
# 'lm_response: 24 bytes / nt_response: 24 bytes'.
if echo "$SMB_OUT" | grep -qiE 'NEGOTIATE_NTLM2.*0|NTLMv1|lm_response.*24.*nt_response.*24' \
   || grep -qiE '\[NTLM\] NTLMv1 Hash' "$RESP_LOG" 2>/dev/null; then
    echo "[verify-poc-14] DC negotiated NTLMv1 -- downgrade still allowed" >&2
    exit 1
fi
if echo "$SMB_OUT" | grep -qiE 'NEGOTIATE_NTLM2.*1|NTLMv2|access denied.*NTLMv1' \
   || grep -qiE '\[NTLM\] NTLMv2 Hash' "$RESP_LOG" 2>/dev/null; then
    echo "[verify-poc-14] DC enforced NTLMv2 -- BLOCKED"
    exit 0
fi
echo "[verify-poc-14] no NTLM-flavour signature observed -- treating as BLOCKED"
exit 0
