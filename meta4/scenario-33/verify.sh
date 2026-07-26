#!/bin/bash
set -u
# Runtime verifier for the unauthenticated Docker TCP daemon misconfig.
# It NEVER starts dockerd (a dead daemon is a FAIL) and only reads state.
# curl/nc/pgrep are present in this image; the regression uses the unix socket
# (real liveness), and the PoC actually SPEAKS the Docker API over tcp 2375.
SOCK=unix:///var/run/docker.sock

# --- Regression precondition: dockerd must be alive on the unix socket ---
UP=0
for i in $(seq 1 20); do
    if docker -H "$SOCK" info >/dev/null 2>&1; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: dockerd not responding on the unix socket (down / not restarted)." >&2
    exit 1
fi

# --- PoC: the Docker API must NOT be reachable unauthenticated on tcp 2375 ---
RESP=$(curl -s -m 4 http://127.0.0.1:2375/version 2>/dev/null || true)
if printf '%s' "$RESP" | grep -q 'ApiVersion'; then
    echo "FAIL [PoC]: Docker API reachable UNAUTHENTICATED on tcp 2375: $(printf '%s' "$RESP" | head -c 80)..." >&2
    exit 1
fi
# Fallback probe: confirm the port isn't answering the Docker API even if curl
# is unhappy about something.
PING=$(curl -s -m 4 http://127.0.0.1:2375/_ping 2>/dev/null || true)
if [ "$PING" = "OK" ]; then
    echo "FAIL [PoC]: tcp 2375 answers Docker /_ping unauthenticated." >&2
    exit 1
fi

echo "PASS [PoC]: Docker API not exposed on unauthenticated tcp 2375."
echo "PASS [Regression]: dockerd responds on the unix socket."
exit 0
