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
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.

set -u
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

###############################################################################
# Liveness: the dRuby service must already be running. Never start it here.
###############################################################################
if ! pgrep -f drb_service.rb >/dev/null 2>&1; then
    echo "FAIL [Regression]: dRuby service is not running — a dead service is a" >&2
    echo "                   failure (verify.sh must not start it)." >&2
    exit 1
fi

IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -z "${IP:-}" ] && IP=$(hostname -i 2>/dev/null | awk '{print $1}')
if [ -z "${IP:-}" ] || [ "${IP#127.}" != "$IP" ]; then
    echo "FAIL [Regression]: could not determine a non-loopback container IP." >&2
    exit 1
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

# Wait for the service to answer a legitimate local ping before probing.
UP=0
for i in $(seq 1 15); do
    if drb_call "druby://127.0.0.1:8787" 'ping' | grep -q 'DRB_OK'; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: local client could not reach dRuby .ping — service down/broken." >&2
    exit 1
fi

###############################################################################
# PoC: remote RCE from the untrusted IP must be refused.
###############################################################################
RCE=$(drb_call "druby://$IP:8787" 'exec_command("id")')
if echo "$RCE" | grep -q 'uid='; then
    echo "FAIL [PoC]: exec_command reached over druby://$IP:8787 and ran as:" >&2
    echo "            $(echo "$RCE" | head -1)" >&2
    echo "            the dRuby RCE is still exposed to untrusted clients." >&2
    exit 1
fi
echo "PASS [PoC]: dRuby RCE unreachable from untrusted IP $IP (got: $(echo "$RCE" | head -1))."

###############################################################################
# Regression: local client still works.
###############################################################################
PING=$(drb_call "druby://127.0.0.1:8787" 'ping')
if ! echo "$PING" | grep -q 'DRB_OK'; then
    echo "FAIL [Regression]: local client cannot reach dRuby service. got=$PING" >&2
    exit 1
fi
echo "PASS [Regression]: local client still receives DRB_OK."

echo "All checks passed."
exit 0
