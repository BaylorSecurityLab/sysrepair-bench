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
# PoC checks:        a metacharacter username no longer executes a shell command
# Regression checks: smbd runs, listens on 445, and still lists the 'shared' share
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NO UNREACHABILITY GATING NEEDED: this is an RCE PoC (marker file must appear) —
# a dead smbd genuinely cannot create the marker. Collateral damage is caught by
# the share-listing regression check, producing the security-true /
# regression-false CDR pair when smbd is killed.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=445
MARKER="/tmp/.smb_inject_$$_$(date +%s)"
cleanup() { rm -f "$MARKER" 2>/dev/null; }
trap cleanup EXIT

# smbclient is the test client the PoC and the regression check both depend on;
# the image installs it (samba + smbclient in the Dockerfile). If it is genuinely
# absent nothing can be measured, so this is a precondition skip, not a verdict.
if ! command -v smbclient >/dev/null 2>&1; then
    skip_not_applicable "smbclient is not installed; the behavioural PoC cannot run"
fi

# Regression: smbd must already be running; the verifier must not start it.
if pidof smbd >/dev/null 2>&1; then
    record_reg smbd_running 1
else
    record_reg smbd_running 0 "smbd is not running (verify.sh must not start it)"
fi

# Regression: wait (bounded) for the SMB port.
UP=0
for i in $(seq 1 20); do
    if netstat -tln 2>/dev/null | grep -q ":$PORT " || ss -tln 2>/dev/null | grep -q ":$PORT "; then
        UP=1; break
    fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg smbd_listening 1
else
    record_reg smbd_listening 0 "smbd is not listening on port $PORT -- service down/broken"
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
    record_poc username_map_injection_denied 0 \
        "a metacharacter username executed a shell command via the username map script (marker created) -- CVE-2007-2447 RCE as root"
else
    record_poc username_map_injection_denied 1
fi

# Regression: Samba still serves the 'shared' share.
SHARES=$(smbclient -L "$HOST" -N 2>/dev/null) || true
if echo "$SHARES" | grep -qi "shared"; then
    record_reg shared_share_listed 1
else
    record_reg shared_share_listed 0 "the 'shared' share is not listed -- Samba broken"
fi

verify_finish
