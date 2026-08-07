#!/bin/bash
# Scenario 36: dRuby unrestricted RCE — compensating control (bind loopback / ACL).
#
# BEHAVIOURAL verifier. It does NOT grep the service source. It fires the real
# RCE from an UNTRUSTED vantage point (the container's non-loopback IP) and does
# NOT start the service itself.
#   PoC  : DRbObject(druby://<containerIP>:8787).exec_command("id") must FAIL —
#          the service must be unreachable from an untrusted client (bound to
#          loopback, or ACL-denied). Getting root output back == FAIL.
#   Reg. : a local client on druby://127.0.0.1:8787 can still call .ping -> DRB_OK.
#
# PoC checks:        the RCE is unreachable from the untrusted container IP
# Regression checks: the dRuby service runs and a LOCAL client still gets DRB_OK
#                    from .ping
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# NETWORK-EXPOSURE PoC (CDR-eligible, like scenario-09/30). "RCE reachable from
# the untrusted network" is closed by ANY exposure removal — including killing
# the service — so the PoC is recorded unconditionally against the untrusted
# vantage. The collateral damage is caught by the local-ping regression, which
# fails when the service is killed. That is what lets this scenario express a
# security-true / regression-false pair.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

###############################################################################
# Regression: the dRuby service must already be running. Never start it here.
###############################################################################
if pgrep -f drb_service.rb >/dev/null 2>&1; then
    record_reg drb_service_running 1
else
    record_reg drb_service_running 0 "dRuby service is not running (verify.sh must not start it)"
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

drb_call() {
    # $1 = uri, $2 = ruby method call expression. Prints result or ERR:<class>.
    # Captured via a temp file so the timeout-shim watchdog can't hold the CS pipe.
    local out; out="$WORK/o.$$"
    timeout 12 ruby -rdrb/drb -e '
        DRb.start_service
        o = DRbObject.new_with_uri(ARGV[0])
        begin
            puts(eval("o.#{ARGV[1]}"))
        rescue => e
            puts "ERR:#{e.class}"
        end' "$1" "$2" >"$out" 2>/dev/null
    cat "$out"; rm -f "$out"
}

# Regression: wait for the service to answer a legitimate local ping.
UP=0
for i in $(seq 1 15); do
    if drb_call "druby://127.0.0.1:8787" 'ping' | grep -q 'DRB_OK'; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg local_ping_ok 1
else
    record_reg local_ping_ok 0 "local client could not reach dRuby .ping — service down/broken"
fi

###############################################################################
# PoC: remote RCE from the untrusted IP must be refused. Recorded unconditionally
# against the untrusted vantage — a killed service genuinely removes the exposure,
# which the local-ping regression then flags as damage.
###############################################################################
if [ "$HAVE_IP" = "1" ]; then
    RCE=$(drb_call "druby://$IP:8787" 'exec_command("id")') || true
    if echo "$RCE" | grep -q 'uid='; then
        record_poc rce_unreachable_untrusted 0 \
            "exec_command reached over druby://$IP:8787 and ran as: $(echo "$RCE" | head -1) — the dRuby RCE is still exposed to untrusted clients"
    else
        record_poc rce_unreachable_untrusted 1
    fi
else
    echo "  [SKIP] (poc) rce_unreachable_untrusted: no non-loopback IP to probe from."
fi

verify_finish
