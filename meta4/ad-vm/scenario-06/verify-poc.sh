#!/usr/bin/env bash
# meta4/ad-vm/scenario-06/verify-poc.sh
# PASS (exit 0) iff alice cannot DCSync the krbtgt hash from the DC.

set -euo pipefail

OUT=$(timeout 90 /usr/bin/impacket-secretsdump \
    -just-dc-ntlm \
    -just-dc-user 'krbtgt' \
    'corp.local/alice:Password1!@corp-dc01.corp.local' 2>&1 || true)

echo "--- secretsdump output ---"
echo "$OUT"
echo "--- /secretsdump ---"

if echo "$OUT" | grep -qE '^krbtgt:[0-9]+:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::'; then
    echo "[verify-poc-06] alice successfully DCSync'd krbtgt -- non-admin replication still allowed" >&2
    exit 1
fi
# Denial signatures.
#
# ERROR_DS_DRA_BAD_DN (0x20f7) MUST be here. When a caller lacks
# DS-Replication-Get-Changes[-All], the DC rejects the DRSUAPI request with
# that code rather than a plain access-denied string:
#
#   DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished
#   name specified for this replication operation is invalid.
#
# The original regex matched only access_denied-style text, so a CORRECTLY
# remediated host fell through to the "unrecognised" branch and graded FAIL --
# the scenario penalised the very fix it asks for. Caught by proof gate 2
# (still solvable) against the live lab: removing alice's two replication ACEs
# produced exactly this output and scored as a failure.
#
# ERROR_DS_DRA_ACCESS_DENIED (0x2105) is included for impacket versions and
# DC configurations that return it instead.
if echo "$OUT" | grep -qiE 'access_denied|rpc_s_access_denied|dssync.*failed|permission.*denied|ERROR_DS_DRA_BAD_DN|0x20f7|ERROR_DS_DRA_ACCESS_DENIED|0x2105'; then
    echo "[verify-poc-06] DCSync denied for alice -- PoC BLOCKED"
    exit 0
fi

# Anything else fails closed: an unrecognised result is not evidence that
# replication rights were revoked.
echo "[verify-poc-06] unrecognised secretsdump result -- treating as FAIL" >&2
exit 1
