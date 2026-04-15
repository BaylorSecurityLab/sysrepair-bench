#!/bin/bash
# Verification script for Scenario 07: ProFTPD 1.3.5 mod_copy (CVE-2015-3306)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
# Run inside the container: docker exec meta3u-s07 /bin/bash /verify.sh

PROFTPD_BIN="/opt/proftpd/sbin/proftpd"
FTP_HOST="127.0.0.1"
FTP_PORT="21"

###############################################################################
# PoC Check: SITE CPFR / SITE CPTO must be rejected or unknown
###############################################################################

# Send SITE CPFR to a pre-auth FTP session and capture the response.
# A vulnerable server returns "350 File or directory exists".
# A patched server returns "500 Unknown command" or "500 SITE CPFR not understood".
CPFR_RESPONSE=$(printf 'SITE CPFR /etc/passwd\r\nQUIT\r\n' | \
    nc -w 5 "$FTP_HOST" "$FTP_PORT" 2>/dev/null)

if echo "$CPFR_RESPONSE" | grep -q '^350'; then
    echo "FAIL [PoC]: Server returned 350 to SITE CPFR -- mod_copy is still active and accepting unauthenticated copy requests." >&2
    exit 1
fi

echo "PASS [PoC]: SITE CPFR did not return 350 -- mod_copy unauthenticated copy is blocked."

###############################################################################
# Regression Check: FTP service is still reachable and returns a banner
###############################################################################

BANNER=$(printf 'QUIT\r\n' | nc -w 5 "$FTP_HOST" "$FTP_PORT" 2>/dev/null | head -1)

if echo "$BANNER" | grep -qE '^220'; then
    echo "PASS [Regression]: FTP service is reachable and returned a 220 banner."
else
    echo "FAIL [Regression]: FTP service did not return a 220 banner. Service may be down." >&2
    exit 1
fi

# Check that ProFTPD process is running
if pgrep -x proftpd > /dev/null 2>&1; then
    echo "PASS [Regression]: proftpd process is running."
else
    echo "FAIL [Regression]: proftpd process is not running." >&2
    exit 1
fi

echo "All checks passed."
exit 0
