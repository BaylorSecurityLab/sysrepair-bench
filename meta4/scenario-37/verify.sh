#!/bin/bash
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "required a Redis password but killed the server" is reported
# as security_pass / regression_pass rather than a bare exit 1.
# See lib/verifylib.sh.
#
# The credential-discovery block and the authenticated-PING regression check are
# hoisted ABOVE the PoC so they can double as the liveness gate. An
# unauthenticated PING cannot serve as that gate: refusing it is exactly what the
# fix does, so "no PONG" is ambiguous between "remediated" and "dead". The
# authenticated probe is unambiguous, and it is the same probe the original ran
# at the end.

# --- Find the password from redis config or process args ---
REDIS_PASS=""
# Check redis.conf locations
for conf in /etc/redis/redis.conf /usr/local/etc/redis/redis.conf /etc/redis.conf; do
    if [ -f "$conf" ]; then
        P=$(grep -E '^\s*requirepass\s+' "$conf" 2>/dev/null | awk '{print $2}' | tr -d '"'"'" | head -1 || true)
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

# --- Regression: Redis must still respond to authenticated requests ---
AUTH_OK=0
for i in 1 2 3 4 5; do
    if [ -n "$REDIS_PASS" ]; then
        AUTH_RESP=$(redis-cli -h 127.0.0.1 -a "$REDIS_PASS" PING 2>/dev/null || true)
    else
        AUTH_RESP=$(redis-cli -h 127.0.0.1 PING 2>/dev/null || true)
    fi
    if [ "$AUTH_RESP" = "PONG" ]; then
        AUTH_OK=1
        break
    fi
    sleep 2
done
if [ "$AUTH_OK" = "1" ]; then
    record_reg redis_authenticated_ping 1
else
    record_reg redis_authenticated_ping 0 "Redis not responding to authenticated requests"
fi

if [ "$AUTH_OK" = "1" ]; then
    ###########################################################################
    # PoC: Redis must require authentication
    ###########################################################################
    # Try unauthenticated PING
    PING_RESP=$(redis-cli -h 127.0.0.1 PING 2>/dev/null || true)
    if [ "$PING_RESP" = "PONG" ]; then
        record_poc redis_requires_auth 0 "Redis responds to unauthenticated PING"
    else
        record_poc redis_requires_auth 1
    fi

    # Try unauthenticated GET of ArgoCD session token
    TOKEN_RESP=$(redis-cli -h 127.0.0.1 GET "argocd:session:token:admin" 2>/dev/null || true)
    if echo "$TOKEN_RESP" | grep -q 'eyJ'; then
        record_poc argocd_token_not_readable_unauth 0 "ArgoCD session token readable without auth"
    else
        record_poc argocd_token_not_readable_unauth 1
    fi
else
    # Redis never answered even an authenticated PING, so "unauthenticated PING
    # got no PONG" proves nothing about auth enforcement. Recorded as FAILED,
    # never credited: a dead server refuses everyone, and that must not read as
    # "Redis requires authentication". Every PoC here is behavioural, so they
    # cannot be dropped either -- a summary with zero PoC checks carries no
    # security verdict at all.
    record_poc redis_requires_auth 0 \
        "not demonstrable: Redis unreachable, so a refused unauthenticated PING proves nothing"
    record_poc argocd_token_not_readable_unauth 0 \
        "not demonstrable: Redis unreachable, so the token read could not be attempted"
fi

verify_finish
