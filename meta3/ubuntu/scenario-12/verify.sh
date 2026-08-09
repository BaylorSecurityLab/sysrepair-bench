#!/bin/bash
# Verification for meta3-ubuntu/scenario-12: WEBrick admin endpoint bound to
# 0.0.0.0:3500. Exit 0 = every check passed, Exit 1 = at least one failed.
#
# DYNAMIC: the bind address is read from the LIVE listener via /proc/net/tcp
# (state 0A = LISTEN, local-addr field is HEX ip:port; 0DAC == 3500). This is
# runtime evidence, so "edited the source but did not restart the process"
# correctly FAILS. `ss` is NOT relied on: on this image ss prints "*:3500" for
# an all-interfaces bind, which never matches a literal 0.0.0.0 grep.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "unbound 0.0.0.0 by killing the admin app" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
    record_poc admin_not_bound_all_ifaces 0 "port 3500 is bound to 0.0.0.0 / :: at runtime -- admin endpoint reachable from all interfaces"
else
    record_poc admin_not_bound_all_ifaces 1
fi

###############################################################################
# Regression: the admin service must still be up and answer on loopback.
###############################################################################
if bound_present; then
    record_reg admin_listener_present 1
else
    record_reg admin_listener_present 0 "nothing is LISTENing on port 3500 -- admin service is down (a dead daemon is a FAIL)"
fi

CODE=$(timeout 8 curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3500/admin 2>/dev/null || true)
if [ "$CODE" = "200" ]; then
    record_reg admin_loopback_200 1
else
    record_reg admin_loopback_200 0 "/admin on loopback returned HTTP '$CODE' (expected 200)"
fi

verify_finish
