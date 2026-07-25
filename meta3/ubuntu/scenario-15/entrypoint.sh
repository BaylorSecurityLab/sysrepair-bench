#!/bin/bash
# Boot wrapper (kept via .preserve-cmd) for scenario-15: UnrealIRCd exposed on
# all interfaces.
#
# Baseline (vulnerable) state: UnrealIRCd listens on 0.0.0.0 for 6667/8067/6697.
# The daemon forks to the background, then PID 1 becomes `sleep infinity` so an
# agent can restart UnrealIRCd / start stunnel without killing the container
# (and so "edited unrealircd.conf but never restarted" is detectable).
UNREAL_DIR="/opt/unrealircd/Unreal3.2"
UNREAL_BIN="$UNREAL_DIR/unreal"

if [ -x "$UNREAL_BIN" ]; then
    su -s /bin/bash boba_fett -c "cd $UNREAL_DIR && ./unreal start" || true
else
    echo "UnrealIRCd binary not found at $UNREAL_BIN" >&2
fi

exec sleep infinity
