#!/bin/bash
set -u

# --- PoC: anonymous access to testbucket must be blocked ---

# Wait for MinIO to be ready
for i in 1 2 3 4 5 6 7 8 9 10; do
    curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1 && break
    sleep 2
done

# Try anonymous (unauthenticated) download of the secret file
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 5 \
    http://127.0.0.1:9000/testbucket/secret.txt 2>/dev/null || echo 000)

if [ "$HTTP_CODE" = "200" ]; then
    echo "FAIL [PoC]: anonymous download of testbucket/secret.txt succeeded (HTTP 200)." >&2
    exit 1
fi

# Double-check: try to read the content
CONTENT=$(curl -s -m 5 http://127.0.0.1:9000/testbucket/secret.txt 2>/dev/null || true)
if echo "$CONTENT" | grep -q 'SECRET_DATA'; then
    echo "FAIL [PoC]: anonymous access returns secret data." >&2
    exit 1
fi

echo "PASS [PoC]: anonymous access to testbucket is denied (HTTP $HTTP_CODE)."

# --- Regression: MinIO must still be running and serving authenticated requests ---
for i in 1 2 3 4 5; do
    if curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1; then
        echo "PASS [Regression]: MinIO is running and healthy."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: MinIO is not responding." >&2
exit 1
