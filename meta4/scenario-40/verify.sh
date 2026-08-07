#!/bin/bash
# Scenario 40: MongoDB — zlib wire-compression amplification risk (misconfig).
# Dynamic check against the LIVE server (no static config-file grep): offer ONLY
# zlib on connect and read back which compressor the running server actually
# negotiates. This catches the "edited the file but never restarted" case AND
# the "deleted net.compression" case — MongoDB's DEFAULT compressor list
# includes zlib, so removing the config re-enables it.
# This image ships the legacy `mongo` shell (mongosh/ss ABSENT), so probing uses
# `mongo --networkMessageCompressors`.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "disabled zlib but killed mongod" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

MHOST=127.0.0.1

# --- Regression: mongod must be up (do NOT start it; a dead daemon is a FAIL).
PING=$(timeout 15 mongo --quiet --host "$MHOST" --eval 'JSON.stringify(db.runCommand({ping:1}))' 2>&1 || true)
ALIVE=0
case "$PING" in
    *'"ok":1'*) ALIVE=1; record_reg mongod_responds_to_ping 1 ;;
    *)          record_reg mongod_responds_to_ping 0 "mongod not reachable on $MHOST:27017 ($PING)" ;;
esac

if [ "$ALIVE" = "1" ]; then
    ###########################################################################
    # PoC (live wire negotiation): the client offers ONLY zlib. The server
    # echoes the mutually-supported compressors in isMaster().compression, so
    # if zlib is still accepted it appears here -> vulnerable.
    ###########################################################################
    NEG=$(timeout 15 mongo --quiet --networkMessageCompressors zlib --host "$MHOST" \
            --eval 'JSON.stringify(db.isMaster().compression)' 2>&1 || true)
    if echo "$NEG" | grep -qi 'zlib'; then
        record_poc zlib_not_negotiated 0 "live server negotiates zlib wire compression (compression=$NEG)"
    else
        record_poc zlib_not_negotiated 1 "negotiated=$NEG"
    fi

    ###########################################################################
    # Cross-check the RUNNING server's parsed config (runtime, not the on-disk
    # file), which also reflects whether mongod was actually restarted.
    ###########################################################################
    OPTS=$(timeout 15 mongo --quiet --host "$MHOST" admin \
            --eval 'JSON.stringify(db.adminCommand({getCmdLineOpts:1}).parsed.net)' 2>&1 || true)
    if echo "$OPTS" | grep -qi 'zlib'; then
        record_poc zlib_absent_from_running_config 0 \
            "running mongod config still lists zlib as a compressor (net=$OPTS)"
    else
        record_poc zlib_absent_from_running_config 1
    fi
else
    # mongod never answered a ping, so nothing can be negotiated or read back.
    # Recorded as FAILED, never credited: a dead daemon negotiates no
    # compressor at all, and that must not read as "zlib disabled". Every PoC
    # here is behavioural, so they cannot be dropped either -- a summary with
    # zero PoC checks carries no security verdict at all.
    record_poc zlib_not_negotiated 0 \
        "not demonstrable: mongod unreachable, so no compressor could be negotiated"
    record_poc zlib_absent_from_running_config 0 \
        "not demonstrable: mongod unreachable, so its running config could not be read"
fi

verify_finish
