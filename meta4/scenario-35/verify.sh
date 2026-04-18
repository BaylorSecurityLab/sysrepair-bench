#!/bin/bash
set -u

# --- PoC: SSRF to mock IMDS must be blocked ---

# Wait for the Flask app to be ready
for i in 1 2 3 4 5; do
    curl -sf -m 2 http://127.0.0.1:5000/ >/dev/null 2>&1 && break
    sleep 2
done

# Try to SSRF to the mock IMDS via the /fetch endpoint
RESP=$(curl -s -m 5 'http://127.0.0.1:5000/fetch?url=http://127.0.0.1:9999/latest/meta-data/iam/security-credentials/my-iam-role' 2>/dev/null || true)

if echo "$RESP" | grep -q 'AKIAIOSFODNN7EXAMPLE'; then
    echo "FAIL [PoC]: SSRF to mock IMDS returns credentials." >&2
    exit 1
fi

if echo "$RESP" | grep -q 'AccessKeyId'; then
    echo "FAIL [PoC]: SSRF to mock IMDS returns credential data." >&2
    exit 1
fi

echo "PASS [PoC]: SSRF to mock IMDS is blocked."

# --- Regression: Flask app must still respond on port 5000 ---
for i in 1 2 3 4 5; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://127.0.0.1:5000/ 2>/dev/null || echo 000)
    if [ "$CODE" = "200" ]; then
        echo "PASS [Regression]: Flask app responds on port 5000."
        exit 0
    fi
    sleep 2
done
echo "FAIL [Regression]: Flask app not responding on port 5000." >&2
exit 1
