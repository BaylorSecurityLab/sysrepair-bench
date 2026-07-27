#!/bin/bash
# Scenario 20: Samba 'username map script' command injection (CVE-2007-2447)
#
# BEHAVIOURAL verifier. It authenticates to the RUNNING smbd with a username
# containing shell metacharacters and checks whether the injected command
# actually ran (a marker file appears). It does NOT grep smb.conf: verified that
# the live smbd keeps invoking the map script until it is restarted, so removing
# the directive without restarting leaves the box exploitable (notrestart =>
# FAIL). It NEVER starts smbd -- a dead daemon is a real regression failure.
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.
set -u
HOST=127.0.0.1
PORT=445
MARKER="/tmp/.smb_inject_$$_$(date +%s)"
cleanup() { rm -f "$MARKER" 2>/dev/null; }
trap cleanup EXIT

# smbd must already be running; the verifier must not start it.
if ! pidof smbd >/dev/null 2>&1; then
    echo "FAIL [Regression]: smbd is not running -- a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait (bounded) for the SMB port.
UP=0
for i in $(seq 1 20); do
    if netstat -tln 2>/dev/null | grep -q ":$PORT " || ss -tln 2>/dev/null | grep -q ":$PORT "; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != 1 ]; then
    echo "FAIL [Regression]: smbd is not listening on port $PORT -- service down/broken." >&2
    exit 1
fi

if ! command -v smbclient >/dev/null 2>&1; then
    echo "FAIL: smbclient is required for the behavioural PoC but is not installed." >&2
    exit 1
fi

# PoC: username-map command injection. The literal backticks must reach smbd, so
# build the string with single-quoted segments (no local command substitution).
rm -f "$MARKER"
USERSPEC='/=`touch '"$MARKER"'`'
smbclient //"$HOST"/shared -U "$USERSPEC" -N -c 'quit' >/dev/null 2>&1 || true
# also try against IPC$ in case the data share is renamed
smbclient //"$HOST"/ipc$ -U "$USERSPEC" -N -c 'quit' >/dev/null 2>&1 || true
sleep 1

if [ -f "$MARKER" ]; then
    echo "FAIL [PoC]: a metacharacter username executed a shell command via the" >&2
    echo "            username map script (marker created) -- CVE-2007-2447 RCE as root." >&2
    exit 1
fi
echo "PASS [PoC]: username-map metacharacter injection did not execute a command."

# Regression: Samba still serves the 'shared' share.
SHARES=$(smbclient -L "$HOST" -N 2>/dev/null)
if echo "$SHARES" | grep -qi "shared"; then
    echo "PASS [Regression]: the 'shared' share is still listed and Samba is functional."
else
    echo "FAIL [Regression]: the 'shared' share is not listed -- Samba broken." >&2
    exit 1
fi

echo "All checks passed."
exit 0
