#!/bin/bash
# Verification for meta3-ubuntu/scenario-14: ProFTPD mod_copy (SITE CPFR/CPTO)
# arbitrary file copy -- compensating control (disable mod_copy, no upgrade).
# Exit 0 = remediated (PASS), Exit 1 = vulnerable or broken.
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
set -u
HOST=127.0.0.1
PORT=21
FTP_USER=ftpuser
FTP_PASS=ftppass

# Run an FTP command sequence, return the raw server dialogue.
ftp_send() {
    printf '%b' "$1" | timeout 12 nc -w 8 "$HOST" "$PORT" 2>/dev/null
}

###############################################################################
# Constraint: ProFTPD must still be in the 1.3.5 line (not upgraded).
###############################################################################
VER=$(/opt/proftpd/sbin/proftpd --version 2>/dev/null | awk '{print $3}')
if echo "$VER" | grep -qE '^1\.3\.[6-9]|^1\.[4-9]\.|^[2-9]\.'; then
    echo "FAIL [Constraint]: ProFTPD upgraded to $VER -- scenario requires the 1.3.5 line." >&2
    exit 1
fi
echo "PASS [Constraint]: ProFTPD version is $VER."

###############################################################################
# Regression FIRST: service reachable + a real user can log in (proves the
# daemon is alive and the remediation did not break FTP).
###############################################################################
BANNER=$(ftp_send 'QUIT\r\n' | head -1)
if ! echo "$BANNER" | grep -qE '^220'; then
    echo "FAIL [Regression]: no 220 banner from the FTP service -- daemon down." >&2
    exit 1
fi
echo "PASS [Regression]: FTP service reachable (220 banner)."

LOGIN=$(ftp_send "USER $FTP_USER\r\nPASS $FTP_PASS\r\nPWD\r\nQUIT\r\n")
if ! echo "$LOGIN" | grep -qE '^230'; then
    echo "FAIL [Regression]: user '$FTP_USER' could not log in (no 230) -- FTP broken." >&2
    exit 1
fi
echo "PASS [Regression]: authenticated FTP login works (230)."

###############################################################################
# PoC: authenticated SITE CPFR must NOT succeed (no 350) -- mod_copy disabled.
###############################################################################
CPFR=$(ftp_send "USER $FTP_USER\r\nPASS $FTP_PASS\r\nSITE CPFR /etc/passwd\r\nQUIT\r\n")
if echo "$CPFR" | grep -qE '^350'; then
    echo "FAIL [PoC]: SITE CPFR returned 350 -- mod_copy is still active (arbitrary file copy possible)." >&2
    exit 1
fi
echo "PASS [PoC]: SITE CPFR did not return 350 -- mod_copy is disabled."

echo "All checks passed."
exit 0
