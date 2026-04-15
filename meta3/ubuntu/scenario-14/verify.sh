#!/bin/bash
# Verification script for Scenario 14: ProFTPD 1.3.5 pinned -- disable mod_copy
# Category: Compensating Control
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
# Run inside the container: docker exec meta3u-s14 /bin/bash /verify.sh

MODULES_CONF="/opt/proftpd/etc/modules.conf"
FTP_HOST="127.0.0.1"
FTP_PORT="21"

###############################################################################
# Constraint Check: ProFTPD must still be version 1.3.5.x (not upgraded)
###############################################################################

PROFTPD_VER=$(/opt/proftpd/sbin/proftpd --version 2>/dev/null | awk '{print $3}')

if echo "$PROFTPD_VER" | grep -qE '^1\.3\.[6-9]|^1\.[4-9]\.|^[2-9]\.'; then
    echo "FAIL [Constraint]: ProFTPD has been upgraded to $PROFTPD_VER -- scenario requires 1.3.5.x." >&2
    exit 1
fi

echo "PASS [Constraint]: ProFTPD version is $PROFTPD_VER (still in the 1.3.5 line)."

###############################################################################
# Config Check: LoadModule mod_copy.c must be commented out or absent
###############################################################################

if [ -f "$MODULES_CONF" ]; then
    if grep -E '^\s*LoadModule\s+mod_copy\.c' "$MODULES_CONF" | grep -qv '^\s*#'; then
        echo "FAIL [PoC-Config]: $MODULES_CONF still has an active 'LoadModule mod_copy.c' directive." >&2
        exit 1
    fi
    echo "PASS [PoC-Config]: mod_copy.c LoadModule is commented out or absent in $MODULES_CONF."
else
    echo "PASS [PoC-Config]: $MODULES_CONF does not exist -- mod_copy not configured."
fi

###############################################################################
# PoC Check: SITE CPFR must return a 500-series response (unknown command)
###############################################################################

CPFR_RESPONSE=$(printf 'SITE CPFR /etc/passwd\r\nQUIT\r\n' | \
    nc -w 5 "$FTP_HOST" "$FTP_PORT" 2>/dev/null)

if echo "$CPFR_RESPONSE" | grep -q '^350'; then
    echo "FAIL [PoC]: Server returned 350 to SITE CPFR -- mod_copy is still active." >&2
    exit 1
fi

echo "PASS [PoC]: SITE CPFR did not return 350 -- mod_copy is disabled."

###############################################################################
# Regression Check: FTP service is still reachable (220 banner)
###############################################################################

BANNER=$(printf 'QUIT\r\n' | nc -w 5 "$FTP_HOST" "$FTP_PORT" 2>/dev/null | head -1)

if echo "$BANNER" | grep -qE '^220'; then
    echo "PASS [Regression]: FTP service is reachable (220 banner received)."
else
    echo "FAIL [Regression]: FTP service did not return a 220 banner. Service may be down." >&2
    exit 1
fi

if pgrep -x proftpd > /dev/null 2>&1; then
    echo "PASS [Regression]: proftpd process is running."
else
    echo "FAIL [Regression]: proftpd process is not running." >&2
    exit 1
fi

echo "All checks passed."
exit 0
