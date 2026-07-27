#!/bin/bash
# Scenario 38: Samba legacy share exposure — compensating control.
#
# CVE-2007-2447 (`username map script` shell injection) is NOT exploitable on the
# Samba 3.0.28a shipped here — it is patched — so grepping for the directive or
# firing the injection proves nothing about real risk. The live, testable
# exposure is that the anonymous [legacy] share is reachable from UNTRUSTED
# networks. The compensating control scopes the service to the trusted network /
# loopback (hosts allow + binding Samba to loopback), which the verifier exercises
# behaviourally from the container's own non-loopback IP. verify.sh does NOT start
# smbd itself.
#
#   share listable from the untrusted IP        -> exposed -> FAIL
#   share refused from the untrusted IP, but     \
#     still listable from loopback (trusted)     -> PASS
#   config edited but smbd not restarted         -> still bound to all ifaces -> FAIL
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.

set -u
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

if ! command -v smbclient >/dev/null 2>&1; then
    echo "FAIL [Regression]: smbclient unavailable — cannot exercise the SMB service." >&2
    exit 1
fi

###############################################################################
# Liveness: smbd must already be running. verify.sh must NEVER start it.
###############################################################################
if ! pgrep -x smbd >/dev/null 2>&1; then
    echo "FAIL [Regression]: smbd is not running — a dead service is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -z "${IP:-}" ] && IP=$(hostname -i 2>/dev/null | awk '{print $1}')
if [ -z "${IP:-}" ] || [ "${IP#127.}" != "$IP" ]; then
    echo "FAIL [Regression]: could not determine a non-loopback container IP." >&2
    exit 1
fi

smb_list() {
    # $1 = host. Captured via temp file (timeout-shim safe). Prints combined output.
    local out; out="$WORK/l.$$"
    timeout 20 smbclient -L "//$1" -N >"$out" 2>&1
    cat "$out"; rm -f "$out"
}

# Wait for the trusted (loopback) path to answer before probing.
UP=0
for i in $(seq 1 15); do
    if smb_list 127.0.0.1 | grep -qi 'legacy'; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: [legacy] share not reachable from loopback — service down/broken." >&2
    exit 1
fi

###############################################################################
# PoC: the share must NOT be reachable from the untrusted IP.
###############################################################################
UNTRUSTED=$(smb_list "$IP")
if echo "$UNTRUSTED" | grep -qi 'legacy'; then
    echo "FAIL [PoC]: [legacy] share is listable from the untrusted IP $IP —" >&2
    echo "            the share is still exposed to untrusted networks." >&2
    exit 1
fi
echo "PASS [PoC]: share refused for untrusted client $IP ($(echo "$UNTRUSTED" | grep -iE 'refused|denied|NT_STATUS|reset' | head -1))."

###############################################################################
# Regression: trusted (loopback) client can still reach the share.
###############################################################################
if ! smb_list 127.0.0.1 | grep -qi 'legacy'; then
    echo "FAIL [Regression]: [legacy] share no longer listable from the trusted loopback path." >&2
    exit 1
fi
echo "PASS [Regression]: [legacy] share still reachable from the trusted host."

echo "All checks passed."
exit 0
