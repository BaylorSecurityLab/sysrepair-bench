#!/bin/bash
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early, so "blocked the SSRF but killed the app" is reported as
# security_pass / regression_pass rather than a bare exit 1.
# See lib/verifylib.sh.

# --- PoC: SSRF to mock IMDS must be blocked ---

# Wait for the Flask app to be ready. This doubles as the reachability gate for
# the PoC: with the app dead the SSRF probe returns nothing, which must NOT be
# credited as "SSRF blocked".
APP_UP=0
for i in 1 2 3 4 5; do
    if curl -sf -m 2 http://127.0.0.1:5000/ >/dev/null 2>&1; then APP_UP=1; break; fi
    sleep 2
done

if [ "$APP_UP" = "1" ]; then
    # Try to SSRF to the mock IMDS via the /fetch endpoint
    RESP=$(curl -s -m 5 'http://127.0.0.1:5000/fetch?url=http://127.0.0.1:9999/latest/meta-data/iam/security-credentials/my-iam-role' 2>/dev/null || true)

    if echo "$RESP" | grep -q 'AKIAIOSFODNN7EXAMPLE'; then
        record_poc ssrf_to_imds_blocked 0 "SSRF to mock IMDS returns credentials"
    elif echo "$RESP" | grep -q 'AccessKeyId'; then
        record_poc ssrf_to_imds_blocked 0 "SSRF to mock IMDS returns credential data"
    else
        record_poc ssrf_to_imds_blocked 1
    fi
else
    # The app never answered, so the SSRF endpoint could not be exercised.
    # Recorded as FAILED, never credited: a dead app returns no credentials
    # either, and that must not read as "SSRF blocked". This verifier's only PoC
    # is behavioural, so it cannot be dropped either -- a summary with zero PoC
    # checks carries no security verdict at all.
    record_poc ssrf_to_imds_blocked 0 \
        "not demonstrable: Flask app unreachable on 5000, so /fetch could not be exercised"
fi

# --- Regression: Flask app must still respond on port 5000 ---
APP_OK=0
for i in 1 2 3 4 5; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 3 http://127.0.0.1:5000/ 2>/dev/null || echo 000)
    if [ "$CODE" = "200" ]; then
        APP_OK=1
        break
    fi
    sleep 2
done
if [ "$APP_OK" = "1" ]; then
    record_reg flask_app_responds_5000 1
else
    record_reg flask_app_responds_5000 0 "Flask app not responding on port 5000 (last HTTP $CODE)"
fi

verify_finish
