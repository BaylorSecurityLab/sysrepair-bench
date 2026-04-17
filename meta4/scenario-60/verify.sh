#!/bin/bash
# Scenario 60: Postfix 3.7 — SMTP Smuggling (CVE-2023-51764)
set -u

###############################################################################
# PoC: smtpd_forbid_bare_newline must be enabled in main.cf
###############################################################################

MAIN_CF="/etc/postfix/main.cf"

if [ ! -f "$MAIN_CF" ]; then
    echo "FAIL [PoC]: Postfix main.cf not found at $MAIN_CF." >&2
    exit 1
fi

if ! grep -qE "smtpd_forbid_bare_newline\s*=\s*yes" "$MAIN_CF" 2>/dev/null; then
    echo "FAIL [PoC]: main.cf does not contain 'smtpd_forbid_bare_newline = yes'." >&2
    exit 1
fi
echo "PASS [PoC]: smtpd_forbid_bare_newline = yes is set in main.cf."

###############################################################################
# Regression: Postfix must still accept EHLO on port 25
###############################################################################

for i in 1 2 3 4 5; do
    RESPONSE=$(echo "EHLO test" | nc -q1 127.0.0.1 25 2>/dev/null || true)
    if echo "$RESPONSE" | grep -q "^250"; then
        echo "PASS [Regression]: Postfix responds to EHLO on port 25."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: Postfix not responding to EHLO on port 25." >&2
exit 1
