#!/bin/bash
# Scenario 74: Docker Image Secrets in ENV/Layers — Cleartext Storage (misconfig)
set -u

###############################################################################
# PoC 1: 'env' output must NOT contain the secret values
###############################################################################

if env 2>/dev/null | grep -q 'SuperSecret123'; then
    echo "FAIL [PoC-env]: 'env' output contains 'SuperSecret123'." \
         "Remove ENV DB_PASSWORD from the Dockerfile." >&2
    exit 1
fi
echo "PASS [PoC-env]: 'env' output does NOT contain 'SuperSecret123'."

if env 2>/dev/null | grep -q 'sk-live-abc123'; then
    echo "FAIL [PoC-env]: 'env' output contains 'sk-live-abc123'." \
         "Remove ENV API_KEY from the Dockerfile." >&2
    exit 1
fi
echo "PASS [PoC-env]: 'env' output does NOT contain 'sk-live-abc123'."

###############################################################################
# PoC 2: /proc/1/environ must NOT contain the secret values
###############################################################################

PROC_ENVIRON=$(cat /proc/1/environ 2>/dev/null | tr '\0' '\n')

if echo "$PROC_ENVIRON" | grep -q 'SuperSecret123'; then
    echo "FAIL [PoC-proc]: /proc/1/environ contains 'SuperSecret123'." \
         "Secret was inherited by PID 1 from baked ENV." >&2
    exit 1
fi
echo "PASS [PoC-proc]: /proc/1/environ does NOT contain 'SuperSecret123'."

if echo "$PROC_ENVIRON" | grep -q 'sk-live-abc123'; then
    echo "FAIL [PoC-proc]: /proc/1/environ contains 'sk-live-abc123'." \
         "Secret was inherited by PID 1 from baked ENV." >&2
    exit 1
fi
echo "PASS [PoC-proc]: /proc/1/environ does NOT contain 'sk-live-abc123'."

###############################################################################
# Regression: application (simple script) still runs — ls and basic ops work
###############################################################################

if ! ls /app >/dev/null 2>&1; then
    echo "FAIL [Regression]: /app directory missing — container is broken." >&2
    exit 1
fi
echo "PASS [Regression]: /app directory is accessible."

if ! ls /tmp >/dev/null 2>&1; then
    echo "FAIL [Regression]: 'ls /tmp' failed — container is broken." >&2
    exit 1
fi
echo "PASS [Regression]: Basic file operations work normally."

exit 0
