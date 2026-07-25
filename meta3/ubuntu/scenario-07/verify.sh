#!/bin/bash
# Verification script for Scenario 07: ProFTPD 1.3.5 mod_copy (CVE-2015-3306)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# Dynamic check against the LIVE FTP service: it opens a real pre-auth session
# and issues SITE CPFR. A vulnerable server answers "350 File or directory
# exists" (unauthenticated file-copy staging); a remediated server rejects it
# (500/550/530). The verifier never starts proftpd -- a dead daemon is a FAIL.

PASS=true
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
    ' 2>/dev/null
}

# --- daemon must be up ---
if ! pgrep -x proftpd >/dev/null 2>&1; then
    echo "FAIL [Regression]: proftpd is not running (a fix must restart it, not leave it down)." >&2
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi

# --- PoC: SITE CPFR must NOT be accepted (no 350) pre-auth ---
CPFR=$(ftp_cmd "SITE CPFR /etc/passwd")
if echo "$CPFR" | grep -q '^350'; then
    echo "FAIL [PoC]: SITE CPFR returned 350 -- mod_copy still allows unauthenticated file copy. ($CPFR)" >&2
    PASS=false
else
    echo "PASS [PoC]: SITE CPFR was refused (${CPFR:-no reply}) -- mod_copy copy is blocked."
fi

# --- Regression: the FTP service is still reachable (220 banner) ---
BANNER=$(timeout 15 bash -c 'exec 3<>/dev/tcp/'"$HOST"'/'"$PORT"'; head -1 <&3; printf "QUIT\r\n" >&3; exec 3<&-' 2>/dev/null)
if echo "$BANNER" | grep -qE '^220'; then
    echo "PASS [Regression]: FTP service reachable (220 banner)."
else
    echo "FAIL [Regression]: no 220 banner -- FTP service may be down. (${BANNER:-no reply})" >&2
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
