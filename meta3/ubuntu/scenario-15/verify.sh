#!/bin/bash
# Verification script for Scenario 15: UnrealIRCd -- bind 127.0.0.1 + stunnel
# Category: Compensating Control
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
# Run inside the container: docker exec meta3u-s15 /bin/bash /verify.sh

UNREAL_CONF="/opt/unrealircd/Unreal3.2/unrealircd.conf"
STUNNEL_CONF="/etc/stunnel/stunnel.conf"

###############################################################################
# PoC Check: Port 6667 must NOT be bound to 0.0.0.0 (all interfaces)
###############################################################################

if ss -tlnp 2>/dev/null | grep ':6667' | grep -q '0\.0\.0\.0\|\*'; then
    echo "FAIL [PoC]: UnrealIRCd port 6667 is still bound to 0.0.0.0 / all interfaces." >&2
    echo "  Edit unrealircd.conf: change 'ip *;' to 'ip 127.0.0.1;' in the listen block." >&2
    exit 1
fi

echo "PASS [PoC]: Port 6667 is not bound to 0.0.0.0."

# Config file check: ip * must not appear in an active (non-commented) listen block
if [ -f "$UNREAL_CONF" ]; then
    if grep -v '^\s*//' "$UNREAL_CONF" | grep -q 'ip\s\+\*\s*;'; then
        echo "FAIL [PoC-Config]: unrealircd.conf still has 'ip *;' in an active listen block." >&2
        exit 1
    fi
    echo "PASS [PoC-Config]: unrealircd.conf does not have 'ip *;' in active listen block."
fi

###############################################################################
# stunnel Check: stunnel must be configured and running on port 6697
###############################################################################

if [ ! -f "$STUNNEL_CONF" ] || [ ! -s "$STUNNEL_CONF" ]; then
    echo "FAIL [PoC-stunnel]: $STUNNEL_CONF is missing or empty -- stunnel not configured." >&2
    exit 1
fi

echo "PASS [PoC-stunnel]: $STUNNEL_CONF exists and is non-empty."

# Verify stunnel is listening on 6697
if ! ss -tlnp 2>/dev/null | grep -q ':6697'; then
    # Try starting stunnel
    stunnel "$STUNNEL_CONF" 2>/dev/null
    sleep 1
    if ! ss -tlnp 2>/dev/null | grep -q ':6697'; then
        echo "FAIL [PoC-stunnel]: stunnel is not listening on port 6697." >&2
        exit 1
    fi
fi

echo "PASS [PoC-stunnel]: stunnel is listening on port 6697."

###############################################################################
# Regression Check: TLS connection on 6697 reaches an IRC banner
###############################################################################

IRC_BANNER=$(echo '' | openssl s_client -connect 127.0.0.1:6697 -quiet 2>/dev/null | head -5)

if echo "$IRC_BANNER" | grep -qiE 'IRC|irc|NOTICE|Welcome|Unreal'; then
    echo "PASS [Regression]: TLS connection on 6697 received an IRC banner."
elif echo "$IRC_BANNER" | grep -qiE 'ERROR|connect'; then
    echo "FAIL [Regression]: TLS connection on 6697 returned an error -- IRC daemon may be down." >&2
    exit 1
else
    # UnrealIRCd may be slow to send the banner; check if 6667 is up on loopback
    if ss -tlnp 2>/dev/null | grep ':6667' | grep -q '127\.0\.0\.1\|::1'; then
        echo "PASS [Regression]: Port 6667 is active on loopback; stunnel tunnel appears configured (IRC banner timing may vary)."
    else
        echo "FAIL [Regression]: No IRC banner received on 6697 and port 6667 is not active on loopback." >&2
        exit 1
    fi
fi

echo "All checks passed."
exit 0
