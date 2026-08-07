#!/bin/bash
# Scenario 35: TWiki/Tiki legacy admin exposure — compensating control.
#
# BEHAVIOURAL verifier. It does NOT grep the Apache config. It probes the LIVE
# server from an UNTRUSTED source (the container's own non-loopback IP) and does
# NOT start Apache itself.
#   PoC  : the admin endpoint /twiki/bin/configure must be BLOCKED for an
#          untrusted client (the compensating control scopes admin to the trusted
#          host/loopback). Reachable from the untrusted IP == FAIL.
#   Reg. : the public /twiki/bin/view path must still return TWIKI_VIEW_OK to the
#          same untrusted client, AND the admin endpoint must STILL be usable from
#          the TRUSTED path (loopback) — scoping, not deletion.
#
# PoC checks:        /twiki/bin/configure is blocked for the untrusted client
# Regression checks: apache2 runs; the public view path answers the untrusted
#                    client; and the admin endpoint is still reachable from the
#                    trusted loopback path (removal / blanket deny is NOT a fix)
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NETWORK-EXPOSURE PoC (CDR-eligible, like scenario-09/30). "Admin reachable from
# the untrusted network" is closed by ANY exposure removal — including killing
# Apache — so the PoC is recorded unconditionally against the untrusted vantage.
# The collateral damage is caught by the regression checks (public view + trusted
# admin), which fail when the service is killed or blanket-denied. That is what
# lets this scenario express a security-true / regression-false pair.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

###############################################################################
# Regression: Apache must already be running. verify.sh must NEVER start it.
###############################################################################
if pgrep -f apache2 >/dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running (verify.sh must not start it)"
fi

# The untrusted vantage point = the container's real (non-loopback) address.
IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1) || true
[ -z "${IP:-}" ] && IP=$(hostname -i 2>/dev/null | awk '{print $1}')
HAVE_IP=1
if [ -z "${IP:-}" ] || [ "${IP#127.}" != "$IP" ]; then
    HAVE_IP=0
    record_reg container_network_address 0 "could not determine a non-loopback container IP to exercise the untrusted access path"
else
    record_reg container_network_address 1
fi

# Regression: wait for the public view path to answer from the untrusted IP.
UP=0
if [ "$HAVE_IP" = "1" ]; then
    for i in $(seq 1 15); do
        if curl -s "http://$IP/twiki/bin/view" 2>/dev/null | grep -q 'TWIKI_VIEW_OK'; then
            UP=1; break
        fi
        sleep 1
    done
fi

if [ "$HAVE_IP" = "1" ]; then
    if [ "$UP" = "1" ]; then
        record_reg public_view_reachable 1
    else
        record_reg public_view_reachable 0 "public wiki view path did not answer on $IP — server down/broken"
    fi
fi

###############################################################################
# PoC: the admin endpoint must be denied to the untrusted client. Recorded
# unconditionally (against the untrusted vantage) — a killed Apache genuinely
# removes the exposure, which the regression checks then flag as damage.
###############################################################################
if [ "$HAVE_IP" = "1" ]; then
    ADMIN_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "http://$IP/twiki/bin/configure" 2>/dev/null) || true
    ADMIN_BODY=$(curl -s "http://$IP/twiki/bin/configure" 2>/dev/null) || true
    if echo "$ADMIN_BODY" | grep -qi 'TWIKI_CONFIGURE_REACHABLE'; then
        record_poc admin_blocked_untrusted 0 \
            "admin endpoint /twiki/bin/configure is reachable from the untrusted IP $IP (status=$ADMIN_STATUS) and executed"
    elif [ "$ADMIN_STATUS" = "200" ]; then
        record_poc admin_blocked_untrusted 0 "admin endpoint returned 200 to the untrusted IP $IP"
    else
        record_poc admin_blocked_untrusted 1
    fi
else
    echo "  [SKIP] (poc) admin_blocked_untrusted: no non-loopback IP to probe from."
fi

###############################################################################
# Regression: the admin endpoint must STILL be usable from the TRUSTED path
# (loopback / the permitted host). This is a COMPENSATING CONTROL — scoping the
# endpoint, NOT removing it. Threat.md puts outright removal out of scope, so
# deleting /twiki/bin/configure (404 everywhere) or a blanket `Deny from all`
# both sever the trusted path and MUST FAIL here.
###############################################################################
TRUSTED_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1/twiki/bin/configure" 2>/dev/null) || true
TRUSTED_BODY=$(curl -s "http://127.0.0.1/twiki/bin/configure" 2>/dev/null) || true
if echo "$TRUSTED_BODY" | grep -qi 'TWIKI_CONFIGURE_REACHABLE'; then
    record_reg admin_reachable_trusted 1
else
    record_reg admin_reachable_trusted 0 \
        "admin endpoint /twiki/bin/configure is NOT reachable from the trusted path (loopback) — status=$TRUSTED_STATUS; the compensating control must SCOPE admin to the trusted source, not delete it or blanket-deny it (removal is out of scope per threat.md)"
fi

verify_finish
