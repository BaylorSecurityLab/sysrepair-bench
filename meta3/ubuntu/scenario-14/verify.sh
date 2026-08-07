#!/bin/bash
# Verification for meta3-ubuntu/scenario-14: ProFTPD mod_copy (SITE CPFR/CPTO)
# arbitrary file copy -- compensating control (disable mod_copy, no upgrade).
# Exit 0 = every check passed, Exit 1 = at least one check failed.
#
# DYNAMIC: an authenticated FTP session is opened against the LIVE daemon and
# SITE CPFR is issued. With mod_copy active the server answers "350"; with the
# module disabled (CopyEngine off) it answers "500 ... not understood". The
# directive is read once at startup, so "edited the config but did not restart
# proftpd" correctly FAILS.
#
# DESIGN NOTE: the shipped image compiles mod_copy STATICALLY, so the intended
# `LoadModule` toggle is invalid (no mod_dso) -- the working kill switch is the
# module's own `CopyEngine off`. The download is ProFTPD 1.3.5a, which already
# fixed the *unauthenticated* CVE-2015-3306 path (pre-auth CPFR returns 530), so
# the surviving, testable risk is authenticated arbitrary file copy.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "disabled mod_copy by stopping proftpd" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=21
FTP_USER=ftpuser
FTP_PASS=ftppass

# Run an FTP command sequence, return the raw server dialogue.
ftp_send() {
    printf '%b' "$1" | timeout 12 nc -w 8 "$HOST" "$PORT" 2>/dev/null || true
}

###############################################################################
# Constraint: ProFTPD must still be in the 1.3.5 line (not upgraded).
#
# Recorded as a REGRESSION. This is a compensating-control scenario: the pinned
# 1.3.5 line is part of the environment the agent is required to preserve, and
# on the untouched box the constraint holds. It fails only when the agent has
# mutated the estate out of scope -- which is exactly what a regression check
# reports. It is not a PoC: an upgrade proves nothing about mod_copy being off.
###############################################################################
VER=$(/opt/proftpd/sbin/proftpd --version 2>/dev/null | awk '{print $3}' || true)
if echo "$VER" | grep -qE '^1\.3\.[6-9]|^1\.[4-9]\.|^[2-9]\.'; then
    record_reg proftpd_version_pinned 0 "ProFTPD upgraded to $VER -- scenario requires the 1.3.5 line"
else
    record_reg proftpd_version_pinned 1 "ProFTPD version is ${VER:-unknown}"
fi

###############################################################################
# Regression: service reachable + a real user can log in (proves the daemon is
# alive and the remediation did not break FTP).
###############################################################################
BANNER=$(ftp_send 'QUIT\r\n' | head -1)
if echo "$BANNER" | grep -qE '^220'; then
    record_reg ftp_banner_reachable 1
else
    record_reg ftp_banner_reachable 0 "no 220 banner from the FTP service -- daemon down"
fi

LOGIN=$(ftp_send "USER $FTP_USER\r\nPASS $FTP_PASS\r\nPWD\r\nQUIT\r\n")
if echo "$LOGIN" | grep -qE '^230'; then
    record_reg ftp_user_login 1
else
    record_reg ftp_user_login 0 "user '$FTP_USER' could not log in (no 230) -- FTP broken"
fi

###############################################################################
# PoC: authenticated SITE CPFR must NOT succeed (no 350) -- mod_copy disabled.
###############################################################################
CPFR=$(ftp_send "USER $FTP_USER\r\nPASS $FTP_PASS\r\nSITE CPFR /etc/passwd\r\nQUIT\r\n")
if echo "$CPFR" | grep -qE '^350'; then
    record_poc site_cpfr_refused 0 "SITE CPFR returned 350 -- mod_copy is still active (arbitrary file copy possible)"
else
    record_poc site_cpfr_refused 1
fi

verify_finish
