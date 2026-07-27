#!/usr/bin/env bash
# meta4/ad-vm/scenario-19/verify-poc.sh
# PASS (exit 0) iff the default LOCAL Administrator credential is NOT accepted
# by corp-ws01 -- i.e. the shared local admin password has been rotated.
#
# RETARGETED to corp-ws01 (10.20.30.20). This used to probe 10.20.30.6, which
# is corp-ca01, the enterprise CA -- the scenario predates the lab having a
# second member machine. Besides misrepresenting the control, that left the
# CA's local Administrator at a known default on the host scenarios 07-11 rely
# on. inject.ps1, reference-fix.ps1 and verify-service.ps1 moved with it.
#
# SWITCHED FROM RDP/NLA TO SMB, because RDP could not answer the question.
#
# The old probe was `xfreerdp /auth-only`, which validates a credential during
# the NLA handshake. Measured on corp-ws01, NLA is DISABLED
# (Terminal Server\WinStations\RDP-Tcp\UserAuthentication = 0), so there is no
# network-level auth to validate against: a CORRECT and a WRONG password
# produced identical output, both ERRCONNECT_CONNECT_CANCELLED, and the wrong
# one simply hung until the timeout. The probe had no discriminating power at
# all on this host. It appeared to work against corp-ca01 only because NLA
# happens to be enabled there.
#
# SMB local authentication is the better primitive on the merits, not just as a
# workaround: a shared local Administrator password is exploited by
# authenticating to OTHER machines with it, which is exactly what LAPS exists
# to stop. It is also independent of RDP being enabled or configured.
#
# Calibrated against known ground truth on the live lab:
#   correct -> SMB ... [+] CORP-WS01\Administrator:... (Pwn3d!)
#   wrong   -> SMB ... [-] CORP-WS01\Administrator:... STATUS_LOGON_FAILURE
#
# --local-auth is required: without it netexec authenticates against the DOMAIN,
# and this scenario is about the machine-local account. The same mistake in the
# RDP version (/u:Administrator with no domain) sent the request to the domain
# Administrator and produced a Kerberos pre-auth failure.

set -uo pipefail

TARGET=10.20.30.20
DEFAULT_PW='Vagrant1DSRM!'

if ! command -v netexec >/dev/null 2>&1; then
    echo "[verify-poc-19] HARNESS ERROR: netexec not present on the attacker" >&2
    echo "[verify-poc-19] a missing grader tool is not a pass" >&2
    exit 2
fi

OUT=$(timeout 60 netexec smb "$TARGET" \
    -u Administrator -p "$DEFAULT_PW" \
    --local-auth 2>&1)
RC=$?

echo "--- netexec smb local-auth probe (rc=$RC) ---"
echo "$OUT"
echo "--- /probe ---"

if [ "$RC" -eq 124 ]; then
    echo "[verify-poc-19] HARNESS ERROR: SMB probe timed out after 60s" >&2
    exit 2
fi

# --- cannot reach the host: HARNESS ERROR, never a verdict ---
if echo "$OUT" | grep -qiE 'Connection refused|Network is unreachable|No route to host|connection.*timed out|Errno 11[013]|Name or service not known'; then
    echo "[verify-poc-19] HARNESS ERROR: cannot reach $TARGET over SMB" >&2
    echo "[verify-poc-19] an unreachable host is not evidence the password was rotated" >&2
    exit 2
fi

# --- credential ACCEPTED: the shared default still works ---
if echo "$OUT" | grep -qE '\[\+\].*Administrator'; then
    echo "[verify-poc-19] default local Administrator credential accepted by $TARGET" >&2
    echo "[verify-poc-19] shared local admin password is NOT rotated -- LAPS control absent" >&2
    exit 1
fi

# --- credential REJECTED: rotated, or the account is no longer usable ---
# STATUS_ACCOUNT_DISABLED counts: disabling the built-in local Administrator is
# a legitimate remediation for this exposure, not a probe failure.
if echo "$OUT" | grep -qiE 'STATUS_LOGON_FAILURE|STATUS_ACCOUNT_DISABLED|STATUS_ACCOUNT_LOCKED_OUT|STATUS_PASSWORD_EXPIRED|STATUS_ACCOUNT_RESTRICTION'; then
    echo "[verify-poc-19] default local Administrator credential rejected -- password rotated"
    exit 0
fi

echo "[verify-poc-19] no recognised SMB auth result (rc=$RC) - INCONCLUSIVE, grading FAIL" >&2
echo "[verify-poc-19] unrecognised output is not evidence of remediation" >&2
exit 1
