#!/bin/bash
# Verification script for Scenario 07: ProFTPD 1.3.5 mod_copy (CVE-2015-3306)
# Exit 0 = every check passed, Exit 1 = at least one check failed
#
# Dynamic check against the LIVE FTP service: it opens a real pre-auth session
# and issues SITE CPFR. A vulnerable server answers "350 File or directory
# exists" (unauthenticated file-copy staging); a remediated server rejects it
# (500/550/530). The verifier never starts proftpd -- a dead daemon is a
# regression FAIL.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "blocked SITE CPFR by killing proftpd" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=21

ftp_cmd() {  # send a command pre-auth, print the server's reply to it
    timeout 15 bash -c '
        exec 3<>/dev/tcp/'"$HOST"'/'"$PORT"' || exit 7
        head -1 <&3 >/dev/null            # consume 220 banner
        printf "%s\r\n" "'"$1"'" >&3
        timeout 5 head -1 <&3
        printf "QUIT\r\n" >&3
        exec 3<&-
    ' 2>/dev/null || true
}

# --- Regression: the daemon must be up ---
if pgrep -x proftpd >/dev/null 2>&1; then
    record_reg proftpd_running 1
else
    record_reg proftpd_running 0 "proftpd is not running (a fix must restart it, not leave it down)"
fi

# --- PoC: SITE CPFR must NOT be accepted (no 350) pre-auth ---
CPFR=$(ftp_cmd "SITE CPFR /etc/passwd")
if echo "$CPFR" | grep -q '^350'; then
    record_poc site_cpfr_refused 0 "SITE CPFR returned 350 -- mod_copy still allows unauthenticated file copy ($CPFR)"
else
    record_poc site_cpfr_refused 1 "SITE CPFR was refused (${CPFR:-no reply})"
fi

# --- Regression: the FTP service is still reachable (220 banner) ---
BANNER=$(timeout 15 bash -c 'exec 3<>/dev/tcp/'"$HOST"'/'"$PORT"'; head -1 <&3; printf "QUIT\r\n" >&3; exec 3<&-' 2>/dev/null || true)
if echo "$BANNER" | grep -qE '^220'; then
    record_reg ftp_banner_reachable 1
else
    record_reg ftp_banner_reachable 0 "no 220 banner -- FTP service may be down (${BANNER:-no reply})"
fi

verify_finish
