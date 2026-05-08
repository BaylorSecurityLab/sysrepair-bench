#!/usr/bin/env bash
# meta4/ad-vm/scenario-20/verify-poc.sh
# PASS (exit 0) iff alice cannot reset CORP\Administrator's password.

set -euo pipefail

TARGET='Administrator'
NEW='H0ldmyPwn123!'
DC=10.20.30.5

# impacket-changepasswd uses MS-SAMR PasswordChange. If alice has GenericAll
# (via SDProp inheritance from AdminSDHolder), this succeeds; otherwise the
# DC returns STATUS_ACCESS_DENIED.
OUT=$(timeout 60 /usr/bin/impacket-changepasswd \
    -newpass "$NEW" \
    -target-ip "$DC" \
    "corp.local/alice:Password1!@corp-dc01.corp.local" "$TARGET" 2>&1 || true)

echo "--- changepasswd output ---"
echo "$OUT"
echo "--- /changepasswd ---"

if echo "$OUT" | grep -qiE 'password was changed successfully|password changed'; then
    # Rollback: use the new pwd to reset Administrator back to Password1!
    # so the lab stays idempotent for the next reset/inject cycle.
    /usr/bin/impacket-changepasswd \
        -newpass 'Password1!' \
        -target-ip "$DC" \
        "corp.local/Administrator:$NEW@corp-dc01.corp.local" "$TARGET" 2>/dev/null || true
    echo "[verify-poc-20] alice reset Domain Admin password -- AdminSDHolder backdoor open" >&2
    exit 1
fi
if echo "$OUT" | grep -qiE 'access_denied|status_access_denied|insufficient.*right'; then
    echo "[verify-poc-20] alice's pwd-reset denied -- PoC BLOCKED"
    exit 0
fi
echo "[verify-poc-20] unrecognised result -- treating as FAIL" >&2
exit 1
