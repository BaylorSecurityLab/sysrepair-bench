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
#          same untrusted client (public read must survive the lockdown).
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.

set -u

###############################################################################
# Liveness: Apache must already be running. verify.sh must NEVER start it.
###############################################################################
if ! pgrep -f apache2 >/dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running — a dead server is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# The untrusted vantage point = the container's real (non-loopback) address.
IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -z "${IP:-}" ] && IP=$(hostname -i 2>/dev/null | awk '{print $1}')
if [ -z "${IP:-}" ] || [ "${IP#127.}" != "$IP" ]; then
    echo "FAIL [Regression]: could not determine a non-loopback container IP to" >&2
    echo "                   exercise the untrusted access path." >&2
    exit 1
fi

# Wait for the public view path to answer from the untrusted IP before probing.
UP=0
for i in $(seq 1 15); do
    if curl -s "http://$IP/twiki/bin/view" 2>/dev/null | grep -q 'TWIKI_VIEW_OK'; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: public wiki view path did not answer on $IP — server down/broken." >&2
    exit 1
fi

###############################################################################
# PoC: the admin endpoint must be denied to the untrusted client.
###############################################################################
ADMIN_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "http://$IP/twiki/bin/configure" 2>/dev/null)
ADMIN_BODY=$(curl -s "http://$IP/twiki/bin/configure" 2>/dev/null)
if echo "$ADMIN_BODY" | grep -qi 'TWIKI_CONFIGURE_REACHABLE'; then
    echo "FAIL [PoC]: admin endpoint /twiki/bin/configure is reachable from the" >&2
    echo "            untrusted IP $IP (status=$ADMIN_STATUS) and executed." >&2
    exit 1
fi
if [ "$ADMIN_STATUS" = "200" ]; then
    echo "FAIL [PoC]: admin endpoint returned 200 to the untrusted IP $IP." >&2
    exit 1
fi
echo "PASS [PoC]: admin endpoint blocked for untrusted client (status=$ADMIN_STATUS)."

###############################################################################
# Regression: public view path still works for the untrusted client.
###############################################################################
VIEW_BODY=$(curl -s "http://$IP/twiki/bin/view" 2>/dev/null)
if ! echo "$VIEW_BODY" | grep -q 'TWIKI_VIEW_OK'; then
    echo "FAIL [Regression]: public TWiki view path no longer reachable. body=$VIEW_BODY" >&2
    exit 1
fi
echo "PASS [Regression]: public wiki view path still reachable from $IP."

###############################################################################
# Regression: the admin endpoint must STILL be usable from the TRUSTED path
# (loopback / the permitted host). This is a COMPENSATING CONTROL — scoping the
# endpoint, NOT removing it. Threat.md puts outright removal out of scope, so:
#   * deleting /twiki/bin/configure (404 everywhere), or
#   * a blanket `Deny from all` with no Allow,
# both sever the trusted path and MUST FAIL here — they are not valid fixes.
###############################################################################
TRUSTED_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1/twiki/bin/configure" 2>/dev/null)
TRUSTED_BODY=$(curl -s "http://127.0.0.1/twiki/bin/configure" 2>/dev/null)
if ! echo "$TRUSTED_BODY" | grep -qi 'TWIKI_CONFIGURE_REACHABLE'; then
    echo "FAIL [Regression]: admin endpoint /twiki/bin/configure is NOT reachable from" >&2
    echo "                   the trusted path (loopback) — status=$TRUSTED_STATUS." >&2
    echo "                   The compensating control must SCOPE admin to the trusted" >&2
    echo "                   source, not delete it or blanket-deny it (removal is out" >&2
    echo "                   of scope per threat.md)." >&2
    exit 1
fi
echo "PASS [Regression]: admin endpoint still reachable from the trusted path (loopback)."

echo "All checks passed."
exit 0
