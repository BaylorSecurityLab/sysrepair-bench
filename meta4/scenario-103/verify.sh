#!/bin/bash
# Scenario 103: cups-browsed RCE (CVE-2024-47177) — Config Hardening
# Checks: cups-browsed disabled OR BrowseRemoteProtocols none; cupsd still runs
set -u

CUPS_BROWSED_CONF="/etc/cups/cups-browsed.conf"

###############################################################################
# PoC: cups-browsed must be inactive OR config disables remote protocols
###############################################################################

BROWSED_INACTIVE=0
CONFIG_HARDENED=0

# Check 1: is cups-browsed service inactive?
if command -v systemctl > /dev/null 2>&1; then
    STATUS=$(systemctl is-active cups-browsed 2>/dev/null || echo "unknown")
    if [ "$STATUS" = "inactive" ] || [ "$STATUS" = "disabled" ]; then
        BROWSED_INACTIVE=1
        echo "PASS [PoC]: cups-browsed service is $STATUS — remote printer browsing disabled."
    fi
fi

# Also check via pgrep if systemctl is unavailable
if [ "$BROWSED_INACTIVE" = "0" ] && ! pgrep -x cups-browsed > /dev/null 2>&1; then
    BROWSED_INACTIVE=1
    echo "PASS [PoC]: cups-browsed process is not running."
fi

# Check 2: BrowseRemoteProtocols set to none in config?
if [ -f "$CUPS_BROWSED_CONF" ] && \
   grep -E '^\s*BrowseRemoteProtocols\s+none' "$CUPS_BROWSED_CONF" > /dev/null 2>&1; then
    CONFIG_HARDENED=1
    echo "PASS [PoC]: BrowseRemoteProtocols is set to 'none' in $CUPS_BROWSED_CONF."
fi

if [ "$BROWSED_INACTIVE" = "0" ] && [ "$CONFIG_HARDENED" = "0" ]; then
    echo "FAIL [PoC]: cups-browsed is running AND BrowseRemoteProtocols is not 'none'." >&2
    echo "       cups-browsed must be stopped/disabled OR BrowseRemoteProtocols set to none." >&2
    exit 1
fi

###############################################################################
# Regression: CUPS (cupsd) must still respond on port 631
###############################################################################

for i in 1 2 3 4 5 6; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        http://localhost:631/ 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|401|403|426)$'; then
        echo "PASS [Regression]: CUPS (cupsd) is reachable on port 631 (HTTP $HTTP_CODE)."
        exit 0
    fi
    # Also accept TCP connectivity as CUPS sometimes returns non-HTTP
    if nc -z localhost 631 2>/dev/null; then
        echo "PASS [Regression]: CUPS (cupsd) is reachable on port 631 (TCP open)."
        exit 0
    fi
    sleep 5
done

echo "FAIL [Regression]: CUPS (cupsd) not reachable on port 631 after remediation." >&2
exit 1
