#!/bin/bash
# Verification script for Scenario 08: Samba USN-7826-2 hardening
#   CVE-2025-9640  (streams_xattr infoleak)   -- checked DYNAMICALLY over SMB
#   CVE-2025-10230 (wins hook command injection) -- checked via config
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# The verifier does NOT start smbd (it is booted by the image CMD); a dead
# daemon is a regression FAIL. smbd re-reads smb.conf on every new connection,
# so the streams_xattr probe reflects the CURRENTLY EFFECTIVE config, not just
# the file. It snapshots/removes any files it creates under the share (trap on
# EXIT).
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "unloaded streams_xattr by killing smbd" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

SHARE_DIR=/srv/samba/public
PROBE="verify_ads_$$"
SMB="smbclient //127.0.0.1/public -U guest% -N"

cleanup() { rm -f "$SHARE_DIR/$PROBE" "$SHARE_DIR/$PROBE".* 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# --- Regression: the daemon must be up ---
if pgrep -x smbd >/dev/null 2>&1; then
    record_reg smbd_running 1
else
    record_reg smbd_running 0 "smbd is not running (a fix must not leave the service down)"
fi

# --- PoC 1 (dynamic): streams_xattr must NOT be active on the live share ---
# Create a base file as the guest, then try to write an NTFS alternate data
# stream. If streams_xattr is loaded the stream is stored as a user.DosStream.*
# xattr; if not, the stream write is rejected.
timeout 25 $SMB -c "put /etc/hostname $PROBE" >/dev/null 2>&1 || true
timeout 25 $SMB -c "put /etc/hostname $PROBE:adstest" >/dev/null 2>&1 || true
if getfattr -d -m - "$SHARE_DIR/$PROBE" 2>/dev/null | grep -qi 'DosStream'; then
    record_poc streams_xattr_inactive 0 "streams_xattr is ACTIVE -- an SMB alternate data stream was stored as an xattr (CVE-2025-9640)"
else
    record_poc streams_xattr_inactive 1
fi
cleanup

# --- PoC 2 (config): the wins hook must be gone and WINS disabled ---
# (nmbd is not started in this image, so the hook is not runtime-reachable; the
# config is the authoritative surface for this directive.)
SMB_CONF=/etc/samba/smb.conf
HOOK=$(grep -iE '^[[:space:]]*wins hook[[:space:]]*=' "$SMB_CONF" 2>/dev/null | grep -v '^[[:space:]]*#' | cut -d= -f2- | tr -d ' \t' || true)
if [ -n "$HOOK" ]; then
    record_poc wins_hook_absent 0 "active 'wins hook' directive present: '$HOOK' (CVE-2025-10230)"
else
    record_poc wins_hook_absent 1
fi
# defence-in-depth: WINS server role should be off
if testparm -s "$SMB_CONF" 2>/dev/null | grep -iqE '^[[:space:]]*wins support[[:space:]]*=[[:space:]]*(yes|true|1)'; then
    record_poc wins_support_disabled 0 "'wins support = yes' still enables the WINS server role (CVE-2025-10230)"
else
    record_poc wins_support_disabled 1
fi

# --- Regression: the file service must still work for a real client ---
if timeout 25 $SMB -c 'ls' 2>/dev/null | grep -q '\.'; then
    record_reg guest_share_access 1
else
    record_reg guest_share_access 0 "guest client could not access the public share"
fi

verify_finish
