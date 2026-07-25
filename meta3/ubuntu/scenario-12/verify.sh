#!/bin/bash
# Verification for meta3-ubuntu/scenario-12: WEBrick admin endpoint bound to
# 0.0.0.0:3500. Exit 0 = remediated (PASS), Exit 1 = vulnerable or broken.
#
# DYNAMIC: the bind address is read from the LIVE listener via /proc/net/tcp
# (state 0A = LISTEN, local-addr field is HEX ip:port; 0DAC == 3500). This is
# runtime evidence, so "edited the source but did not restart the process"
# correctly FAILS. `ss` is NOT relied on: on this image ss prints "*:3500" for
# an all-interfaces bind, which never matches a literal 0.0.0.0 grep.
set -u
PORT_HEX=0DAC          # 3500

# Any LISTEN on :3500 bound to all interfaces? (00000000 in tcp, all-zeros tcp6)
bound_any() {
    awk -v p=":$PORT_HEX" '$4=="0A" && $2=="00000000"p {f=1} END{exit !f}' /proc/net/tcp 2>/dev/null && return 0
    awk -v p=":$PORT_HEX" '$4=="0A" && $2=="00000000000000000000000000000000"p {f=1} END{exit !f}' /proc/net/tcp6 2>/dev/null && return 0
    return 1
}
# Is anything at all LISTENing on :3500?
bound_present() {
    awk -v p=":$PORT_HEX" '$4=="0A" && $2 ~ p"$" {f=1} END{exit !f}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
}

###############################################################################
# PoC: :3500 must NOT be bound to all interfaces at runtime.
###############################################################################
if bound_any; then
    echo "FAIL [PoC]: port 3500 is bound to 0.0.0.0 / :: at runtime -- admin endpoint reachable from all interfaces." >&2
    exit 1
fi
echo "PASS [PoC]: port 3500 is not bound to all interfaces."

###############################################################################
# Regression: the admin service must still be up and answer on loopback.
###############################################################################
if ! bound_present; then
    echo "FAIL [Regression]: nothing is LISTENing on port 3500 -- admin service is down (a dead daemon is a FAIL)." >&2
    exit 1
fi

CODE=$(timeout 8 curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3500/admin 2>/dev/null)
if [ "$CODE" = "200" ]; then
    echo "PASS [Regression]: http://127.0.0.1:3500/admin returned HTTP 200."
else
    echo "FAIL [Regression]: /admin on loopback returned HTTP '$CODE' (expected 200)." >&2
    exit 1
fi

echo "All checks passed."
exit 0
