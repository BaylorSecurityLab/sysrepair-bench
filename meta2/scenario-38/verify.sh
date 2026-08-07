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
# PoC checks:        the [legacy] share is NOT listable from the untrusted IP
# Regression checks: smbclient is available, smbd runs, a non-loopback IP is
#                    resolvable, and the [legacy] share is still listable from the
#                    trusted loopback path
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NETWORK-EXPOSURE PoC (CDR-eligible, like scenario-09/35). "Share reachable from
# the untrusted network" is closed by ANY exposure removal — including killing
# smbd — so the PoC is recorded unconditionally against the untrusted vantage.
# The collateral damage is caught by the trusted-loopback regression, which fails
# when smbd is killed. That lets this scenario express a security-true /
# regression-false pair.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# smbclient is the test client both components depend on; the image provides it.
if ! command -v smbclient >/dev/null 2>&1; then
    skip_not_applicable "smbclient unavailable — cannot exercise the SMB service"
fi

###############################################################################
# Regression: smbd must already be running. verify.sh must NEVER start it.
###############################################################################
if pgrep -x smbd >/dev/null 2>&1; then
    record_reg smbd_running 1
else
    record_reg smbd_running 0 "smbd is not running (verify.sh must not start it)"
fi

IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1) || true
[ -z "${IP:-}" ] && IP=$(hostname -i 2>/dev/null | awk '{print $1}')
HAVE_IP=1
if [ -z "${IP:-}" ] || [ "${IP#127.}" != "$IP" ]; then
    HAVE_IP=0
    record_reg container_network_address 0 "could not determine a non-loopback container IP"
else
    record_reg container_network_address 1
fi

smb_list() {
    # $1 = host. Captured via temp file (timeout-shim safe). Prints combined output.
    local out; out="$WORK/l.$$"
    timeout 20 smbclient -L "//$1" -N >"$out" 2>&1
    cat "$out"; rm -f "$out"
}

# Regression: wait for the trusted (loopback) path to answer before probing.
UP=0
for i in $(seq 1 15); do
    if smb_list 127.0.0.1 | grep -qi 'legacy'; then UP=1; break; fi
    sleep 1
done
if [ "$UP" = "1" ]; then
    record_reg loopback_share_listable 1
else
    record_reg loopback_share_listable 0 "[legacy] share not reachable from loopback — service down/broken"
fi

###############################################################################
# PoC: the share must NOT be reachable from the untrusted IP. Recorded
# unconditionally against the untrusted vantage — a killed smbd genuinely removes
# the exposure, which the loopback regression then flags as damage.
###############################################################################
if [ "$HAVE_IP" = "1" ]; then
    UNTRUSTED=$(smb_list "$IP") || true
    if echo "$UNTRUSTED" | grep -qi 'legacy'; then
        record_poc share_blocked_untrusted 0 \
            "[legacy] share is listable from the untrusted IP $IP — the share is still exposed to untrusted networks"
    else
        record_poc share_blocked_untrusted 1
    fi
else
    echo "  [SKIP] (poc) share_blocked_untrusted: no non-loopback IP to probe from."
fi

verify_finish
