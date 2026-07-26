#!/bin/bash
# Scenario 103: cups-browsed RCE (CVE-2024-47177) — Config Hardening
# Ground truth is BEHAVIORAL: the vulnerable daemon that turns a malicious
# printer advertisement into an attacker-controlled PPD is cups-browsed itself.
# The remediation is to STOP/disable that daemon (or restart it with remote
# browsing off). We assert cups-browsed is NO LONGER RUNNING while cupsd keeps
# serving. cups-browsed boots already-running (.preserve-cmd), so a config edit
# that never stopped/restarted the daemon still leaves it running and FAILs here.
set -u
CONF=/etc/cups/cups-browsed.conf

# Is the cups-browsed daemon still running? Match argv[0] basename exactly so we
# never confuse it with cupsd (do not rely on pgrep being present).
browsed_running() {
    for p in /proc/[0-9]*; do
        a0=$(tr '\0' '\n' < "$p/cmdline" 2>/dev/null | head -1)
        base=${a0##*/}
        [ "$base" = "cups-browsed" ] && return 0
    done
    return 1
}

###############################################################################
# PoC: cups-browsed must not be running. (If a solver instead chose to keep it
# running with BrowseRemoteProtocols none, that is accepted too, but the daemon
# must have been RESTARTED to pick it up — which for this image means it is
# started fresh; a stale process with the old in-memory config still FAILs.)
###############################################################################
if browsed_running; then
    if [ -f "$CONF" ] && grep -Eq '^[[:space:]]*BrowseRemoteProtocols[[:space:]]+none[[:space:]]*$' "$CONF"; then
        # Config says none, but the daemon is still up. cups-browsed reads config
        # only at start, so we cannot confirm the RUNNING daemon honours it —
        # treat a still-running daemon as exposed.
        echo "FAIL [PoC]: cups-browsed is still RUNNING (config says none, but the live daemon was not restarted to apply it)." >&2
        exit 1
    fi
    echo "FAIL [PoC]: cups-browsed is running AND remote browsing is not disabled — malicious-advertisement RCE surface is live." >&2
    exit 1
fi
echo "PASS [PoC]: cups-browsed daemon is not running — malicious-advertisement RCE surface removed."

###############################################################################
# Regression: cupsd must still serve on port 631 (curl is present in this image)
###############################################################################
for i in 1 2 3 4 5 6; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:631/ 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|401|403|426)$'; then
        echo "PASS [Regression]: cupsd is reachable on port 631 (HTTP $HTTP_CODE)."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: cupsd not reachable on port 631 after remediation." >&2
exit 1
