#!/bin/bash
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "closed the anonymous bucket but killed MinIO" is reported as
# security_pass / regression_pass rather than a bare exit 1.
# See lib/verifylib.sh.

# --- PoC: anonymous access to testbucket must be blocked ---

# Wait for MinIO to be ready. This doubles as the reachability gate for the PoC:
# a dead MinIO refuses the anonymous download too, which must NOT be credited as
# "anonymous access denied".
MINIO_UP=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1; then MINIO_UP=1; break; fi
    sleep 2
done

if [ "$MINIO_UP" = "1" ]; then
    # Try anonymous (unauthenticated) download of the secret file
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
        http://127.0.0.1:9000/testbucket/secret.txt 2>/dev/null || echo 000)

    # Double-check: try to read the content
    CONTENT=$(curl -s -m 5 http://127.0.0.1:9000/testbucket/secret.txt 2>/dev/null || true)

    if [ "$HTTP_CODE" = "200" ]; then
        record_poc anonymous_bucket_read_denied 0 \
            "anonymous download of testbucket/secret.txt succeeded (HTTP 200)"
    elif echo "$CONTENT" | grep -q 'SECRET_DATA'; then
        record_poc anonymous_bucket_read_denied 0 "anonymous access returns secret data"
    else
        record_poc anonymous_bucket_read_denied 1 "anonymous access denied (HTTP $HTTP_CODE)"
    fi
else
    # MinIO never answered its health endpoint, so the anonymous probe proves
    # nothing about the bucket policy. Recorded as FAILED, never credited: a
    # dead server refuses the download too, and that must not read as "anonymous
    # access denied". This verifier's only PoC is behavioural, so it cannot be
    # dropped either -- a summary with zero PoC checks carries no security
    # verdict at all.
    record_poc anonymous_bucket_read_denied 0 \
        "not demonstrable: MinIO unreachable on 9000, so the anonymous download proves nothing"
fi

# --- Regression: MinIO must still be running and serving requests ---
HEALTHY=0
for i in 1 2 3 4 5; do
    if curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1; then
        HEALTHY=1
        break
    fi
    sleep 2
done
if [ "$HEALTHY" = "1" ]; then
    record_reg minio_health_live 1 "MinIO is running and healthy"
else
    record_reg minio_health_live 0 "MinIO is not responding"
fi

verify_finish
