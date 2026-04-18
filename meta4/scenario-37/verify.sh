#!/bin/bash
set -u

# --- PoC: Redis must require authentication ---

# Wait for Redis to be ready
for i in 1 2 3 4 5; do
    redis-cli PING >/dev/null 2>&1 && break
    sleep 2
done

# Try unauthenticated PING
PING_RESP=$(redis-cli -h 127.0.0.1 PING 2>/dev/null || true)
if [ "$PING_RESP" = "PONG" ]; then
    echo "FAIL [PoC]: Redis responds to unauthenticated PING." >&2
    exit 1
fi

# Try unauthenticated GET of ArgoCD session token
TOKEN_RESP=$(redis-cli -h 127.0.0.1 GET "argocd:session:token:admin" 2>/dev/null || true)
if echo "$TOKEN_RESP" | grep -q 'eyJ'; then
    echo "FAIL [PoC]: ArgoCD session token readable without auth." >&2
    exit 1
fi

echo "PASS [PoC]: Redis requires authentication."

# --- Regression: Redis must still respond to authenticated requests ---
# Find the password from redis config or process args
REDIS_PASS=""
# Check redis.conf locations
for conf in /etc/redis/redis.conf /usr/local/etc/redis/redis.conf /etc/redis.conf; do
    if [ -f "$conf" ]; then
        P=$(grep -E '^\s*requirepass\s+' "$conf" 2>/dev/null | awk '{print $2}' | tr -d '"'"'" | head -1)
        if [ -n "$P" ]; then
            REDIS_PASS="$P"
            break
        fi
    fi
done

# Check process args if not found in config
if [ -z "$REDIS_PASS" ]; then
    REDIS_PASS=$(ps aux 2>/dev/null | grep -oP '(?<=--requirepass\s)\S+' | head -1 || true)
fi

for i in 1 2 3 4 5; do
    if [ -n "$REDIS_PASS" ]; then
        AUTH_RESP=$(redis-cli -h 127.0.0.1 -a "$REDIS_PASS" PING 2>/dev/null || true)
    else
        AUTH_RESP=$(redis-cli -h 127.0.0.1 PING 2>/dev/null || true)
    fi
    if [ "$AUTH_RESP" = "PONG" ]; then
        echo "PASS [Regression]: Redis responds to authenticated PING."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: Redis not responding to authenticated requests." >&2
exit 1
