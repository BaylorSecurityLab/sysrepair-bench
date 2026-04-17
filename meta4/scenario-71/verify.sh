#!/bin/bash
# Scenario 71: Docker seccomp=unconfined — All Syscalls Allowed (misconfig)
set -u

###############################################################################
# PoC: Seccomp must be in FILTER mode (field = 2) on PID 1
###############################################################################

SECCOMP=$(grep '^Seccomp:' /proc/1/status 2>/dev/null | awk '{print $2}')
if [ -z "$SECCOMP" ]; then
    echo "FAIL [PoC]: Could not read Seccomp field from /proc/1/status." >&2
    exit 1
fi

if [ "$SECCOMP" != "2" ]; then
    echo "FAIL [PoC]: Seccomp is NOT in filter mode (field=$SECCOMP, expected 2)." \
         "Remove --security-opt seccomp=unconfined." >&2
    exit 1
fi
echo "PASS [PoC]: Seccomp is in FILTER mode (field=2). Default profile is active."

###############################################################################
# Regression: normal commands work
###############################################################################

if ! ls /tmp >/dev/null 2>&1; then
    echo "FAIL [Regression]: 'ls /tmp' failed — container is broken." >&2
    exit 1
fi
echo "PASS [Regression]: 'ls /tmp' works normally."

if ! ps aux >/dev/null 2>&1; then
    echo "FAIL [Regression]: 'ps aux' failed — container is broken." >&2
    exit 1
fi
echo "PASS [Regression]: 'ps aux' works normally."

exit 0
