#!/bin/bash
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
# Runtime verifier for the unauthenticated Docker TCP daemon misconfig.
# It NEVER starts dockerd (a dead daemon is a FAIL) and only reads state.
# curl/nc/pgrep are present in this image; the regression uses the unix socket
# (real liveness), and the PoC actually SPEAKS the Docker API over tcp 2375.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "closed tcp 2375 but killed dockerd" is reported as
# security_pass / regression_pass rather than a bare exit 1. See lib/verifylib.sh.
SOCK=unix:///var/run/docker.sock

# --- Regression: dockerd must be alive on the unix socket ---
UP=0
for i in $(seq 1 20); do
    if docker -H "$SOCK" info >/dev/null 2>&1; then UP=1; break; fi
    sleep 1
done
if [ "$UP" = "1" ]; then
    record_reg dockerd_unix_socket 1 "dockerd responds on the unix socket"
else
    record_reg dockerd_unix_socket 0 "dockerd not responding on the unix socket (down / not restarted)"
fi

if [ "$UP" = "1" ]; then
    ###########################################################################
    # PoC: the Docker API must NOT be reachable unauthenticated on tcp 2375
    ###########################################################################
    RESP=$(curl -s -m 4 http://127.0.0.1:2375/version 2>/dev/null || true)
    # Fallback probe: confirm the port isn't answering the Docker API even if
    # curl is unhappy about something.
    PING=$(curl -s -m 4 http://127.0.0.1:2375/_ping 2>/dev/null || true)
    if printf '%s' "$RESP" | grep -q 'ApiVersion'; then
        record_poc docker_api_not_on_tcp_2375 0 \
            "Docker API reachable UNAUTHENTICATED on tcp 2375: $(printf '%s' "$RESP" | head -c 80)..."
    elif [ "$PING" = "OK" ]; then
        record_poc docker_api_not_on_tcp_2375 0 "tcp 2375 answers Docker /_ping unauthenticated"
    else
        record_poc docker_api_not_on_tcp_2375 1
    fi
else
    # dockerd is not answering at all, so "2375 is silent" proves nothing about
    # the configuration. Recorded as FAILED, never credited: killing dockerd
    # also closes 2375, and that must not read as a closed vulnerability. This
    # verifier's only PoC is behavioural, so it cannot be dropped either -- a
    # summary with zero PoC checks carries no security verdict at all.
    record_poc docker_api_not_on_tcp_2375 0 \
        "not demonstrable: dockerd unreachable on its unix socket, so tcp 2375 silence proves nothing"
fi

verify_finish
