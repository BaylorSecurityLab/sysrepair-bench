#!/bin/bash
set -u

# --- PoC: Docker daemon must NOT be reachable on TCP 2375 without auth ---

# Check if TCP 2375 responds with Docker API data (unauthenticated)
RESP=$(curl -s -m 3 http://127.0.0.1:2375/version 2>/dev/null || true)
if echo "$RESP" | grep -q 'ApiVersion'; then
    echo "FAIL [PoC]: Docker API accessible on TCP 2375 without TLS." >&2
    exit 1
fi

# Also check daemon.json for tcp://...2375 without tls
if [ -f /etc/docker/daemon.json ]; then
    if grep -q '"tcp://.*:2375"' /etc/docker/daemon.json 2>/dev/null; then
        # Check if TLS is also enabled
        if ! grep -q '"tlsverify"' /etc/docker/daemon.json 2>/dev/null; then
            echo "FAIL [PoC]: daemon.json still has TCP 2375 without TLS." >&2
            exit 1
        fi
    fi
fi

echo "PASS [PoC]: Docker API not exposed on unauthenticated TCP 2375."

# --- Regression: Docker daemon must still be running ---
for i in 1 2 3 4 5; do
    if pgrep -x dockerd >/dev/null 2>&1; then
        echo "PASS [Regression]: dockerd process is running."
        exit 0
    fi
    if docker info >/dev/null 2>&1; then
        echo "PASS [Regression]: docker info succeeds."
        exit 0
    fi
    sleep 3
done
echo "FAIL [Regression]: dockerd is not running." >&2
exit 1
