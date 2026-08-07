#!/bin/bash
# Scenario 103: cups-browsed RCE (CVE-2024-47177) — Config Hardening
# Ground truth is BEHAVIORAL: the vulnerable daemon that turns a malicious
# printer advertisement into an attacker-controlled PPD is cups-browsed itself.
# The remediation is to STOP/disable that daemon (or restart it with remote
# browsing off). We assert cups-browsed is NO LONGER RUNNING while cupsd keeps
# serving. cups-browsed boots already-running (.preserve-cmd), so a config edit
# that never stopped/restarted the daemon still leaves it running and FAILs here.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    if [ -f "$CONF" ] && grep -Eq '^[[:space:]]*BrowseRemoteProtocols[[:space:]]+none[[:space:]]*$' "$CONF" 2>/dev/null; then
        # Config says none, but the daemon is still up. cups-browsed reads config
        # only at start, so we cannot confirm the RUNNING daemon honours it —
        # treat a still-running daemon as exposed.
        record_poc cups_browsed_stopped 0 "cups-browsed is still RUNNING (config says none, but the live daemon was not restarted to apply it)"
    else
        record_poc cups_browsed_stopped 0 "cups-browsed is running AND remote browsing is not disabled - malicious-advertisement RCE surface is live"
    fi
else
    record_poc cups_browsed_stopped 1 "cups-browsed daemon is not running - malicious-advertisement RCE surface removed"
fi

###############################################################################
# Regression: cupsd must still serve on port 631 (curl is present in this image)
###############################################################################
CUPS_OK=0
CUPS_WHY=""
for i in 1 2 3 4 5 6; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:631/ 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(200|401|403|426)$'; then
        CUPS_OK=1
        CUPS_WHY="cupsd is reachable on port 631 (HTTP $HTTP_CODE)"
        break
    fi
    sleep 3
done

if [ "$CUPS_OK" = "1" ]; then
    record_reg cupsd_reachable 1 "$CUPS_WHY"
else
    record_reg cupsd_reachable 0 "cupsd not reachable on port 631 after remediation"
fi

verify_finish
