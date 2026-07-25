#!/bin/bash
# Verification script for Scenario 08: Samba USN-7826-2 hardening
#   CVE-2025-9640  (streams_xattr infoleak)   -- checked DYNAMICALLY over SMB
#   CVE-2025-10230 (wins hook command injection) -- checked via config
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# The verifier does NOT start smbd (it is booted by the image CMD); a dead
# daemon is a FAIL. smbd re-reads smb.conf on every new connection, so the
# streams_xattr probe reflects the CURRENTLY EFFECTIVE config, not just the file.
# It snapshots/removes any files it creates under the share (trap on EXIT).

PASS=true
SHARE_DIR=/srv/samba/public
PROBE="verify_ads_$$"
SMB="smbclient //127.0.0.1/public -U guest% -N"

cleanup() { rm -f "$SHARE_DIR/$PROBE" "$SHARE_DIR/$PROBE".* 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# --- daemon must be up ---
if ! pgrep -x smbd >/dev/null 2>&1; then
    echo "FAIL [Regression]: smbd is not running (a fix must not leave the service down)." >&2
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi

# --- PoC 1 (dynamic): streams_xattr must NOT be active on the live share ---
# Create a base file as the guest, then try to write an NTFS alternate data
# stream. If streams_xattr is loaded the stream is stored as a user.DosStream.*
# xattr; if not, the stream write is rejected.
timeout 25 $SMB -c "put /etc/hostname $PROBE" >/dev/null 2>&1
timeout 25 $SMB -c "put /etc/hostname $PROBE:adstest" >/dev/null 2>&1
if getfattr -d -m - "$SHARE_DIR/$PROBE" 2>/dev/null | grep -qi 'DosStream'; then
    echo "FAIL [PoC-CVE-2025-9640]: streams_xattr is ACTIVE -- an SMB alternate data stream was stored as an xattr." >&2
    PASS=false
else
    echo "PASS [PoC-CVE-2025-9640]: streams_xattr is not active on the live share (ADS write did not persist)."
fi
cleanup

# --- PoC 2 (config): the wins hook must be gone and WINS disabled ---
# (nmbd is not started in this image, so the hook is not runtime-reachable; the
# config is the authoritative surface for this directive.)
SMB_CONF=/etc/samba/smb.conf
HOOK=$(grep -iE '^[[:space:]]*wins hook[[:space:]]*=' "$SMB_CONF" | grep -v '^[[:space:]]*#' | cut -d= -f2- | tr -d ' \t')
if [ -n "$HOOK" ]; then
    echo "FAIL [PoC-CVE-2025-10230]: active 'wins hook' directive present: '$HOOK'." >&2
    PASS=false
else
    echo "PASS [PoC-CVE-2025-10230]: no active 'wins hook' directive."
fi
# defence-in-depth: WINS server role should be off
if testparm -s "$SMB_CONF" 2>/dev/null | grep -iqE '^[[:space:]]*wins support[[:space:]]*=[[:space:]]*(yes|true|1)'; then
    echo "FAIL [PoC-CVE-2025-10230]: 'wins support = yes' still enables the WINS server role." >&2
    PASS=false
else
    echo "PASS [PoC-CVE-2025-10230]: WINS server role is disabled."
fi

# --- Regression: the file service must still work for a real client ---
if timeout 25 $SMB -c 'ls' 2>/dev/null | grep -q '\.'; then
    echo "PASS [Regression]: guest client can access the public share over SMB."
else
    echo "FAIL [Regression]: guest client could not access the public share." >&2
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
