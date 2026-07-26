#!/bin/bash
# Scenario 40: MongoDB — zlib wire-compression amplification risk (misconfig).
# Dynamic check against the LIVE server (no static config-file grep): offer ONLY
# zlib on connect and read back which compressor the running server actually
# negotiates. This catches the "edited the file but never restarted" case AND
# the "deleted net.compression" case — MongoDB's DEFAULT compressor list
# includes zlib, so removing the config re-enables it.
# This image ships the legacy `mongo` shell (mongosh/ss ABSENT), so probing uses
# `mongo --networkMessageCompressors`.
set -u

MHOST=127.0.0.1

# --- Regression: mongod must be up (do NOT start it; a dead daemon is a FAIL).
PING=$(timeout 15 mongo --quiet --host "$MHOST" --eval 'JSON.stringify(db.runCommand({ping:1}))' 2>&1 || true)
case "$PING" in
    *'"ok":1'*) echo "PASS [Regression]: mongod is up and responds to ping." ;;
    *) echo "FAIL [Regression]: mongod not reachable on $MHOST:27017 ($PING)." >&2; exit 1 ;;
esac

# --- PoC (live wire negotiation): the client offers ONLY zlib. The server
#     echoes the mutually-supported compressors in isMaster().compression, so
#     if zlib is still accepted it appears here -> vulnerable.
NEG=$(timeout 15 mongo --quiet --networkMessageCompressors zlib --host "$MHOST" \
        --eval 'JSON.stringify(db.isMaster().compression)' 2>&1 || true)
if echo "$NEG" | grep -qi 'zlib'; then
    echo "FAIL [PoC]: live server negotiates zlib wire compression (compression=$NEG)." >&2
    exit 1
fi

# --- Cross-check the RUNNING server's parsed config (runtime, not the on-disk
#     file), which also reflects whether mongod was actually restarted.
OPTS=$(timeout 15 mongo --quiet --host "$MHOST" admin \
        --eval 'JSON.stringify(db.adminCommand({getCmdLineOpts:1}).parsed.net)' 2>&1 || true)
if echo "$OPTS" | grep -qi 'zlib'; then
    echo "FAIL [PoC]: running mongod config still lists zlib as a compressor (net=$OPTS)." >&2
    exit 1
fi

echo "PASS [PoC]: zlib wire compression is disabled on the live server (negotiated=$NEG)."
exit 0
