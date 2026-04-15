#!/bin/bash
# Entrypoint for scenario-15: UnrealIRCd pinned -- bind localhost + stunnel front
#
# Pre-remediation state: UnrealIRCd listens on 0.0.0.0:6667 (all interfaces).
# Post-remediation: UnrealIRCd listens on 127.0.0.1:6667 only, stunnel on 0.0.0.0:6697.

UNREAL_DIR="/opt/unrealircd/Unreal3.2"
UNREAL_BIN="$UNREAL_DIR/unreal"

# If stunnel config exists and is non-empty, start stunnel first
if [ -s /etc/stunnel/stunnel.conf ]; then
    stunnel /etc/stunnel/stunnel.conf
fi

# Start UnrealIRCd in foreground (recipe stripped the service block)
if [ -x "$UNREAL_BIN" ]; then
    exec su -s /bin/bash boba_fett -c "cd $UNREAL_DIR && ./unreal start && tail -f $UNREAL_DIR/ircd.log 2>/dev/null || sleep infinity"
else
    echo "UnrealIRCd binary not found at $UNREAL_BIN" >&2
    # Fallback: keep container alive for manual inspection
    exec sleep infinity
fi
