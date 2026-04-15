#!/bin/bash
# Verification script for Scenario 17: payroll_app.php source-locked SQLi — mod_security WAF
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# Pre-flight: mod_security must be loaded and engine must be On
###############################################################################

if ! apache2ctl -M 2>/dev/null | grep -qi 'security2'; then
    echo "FAIL [PoC]: mod_security2 is not loaded in Apache." >&2
    exit 1
fi
echo "PASS [Pre-flight]: mod_security2 module is loaded."

if ! grep -rqi 'SecRuleEngine On' /etc/modsecurity/ 2>/dev/null; then
    echo "FAIL [PoC]: SecRuleEngine is not set to 'On' — WAF is in detection-only mode." >&2
    exit 1
fi
echo "PASS [Pre-flight]: SecRuleEngine is On."

###############################################################################
# PoC Check: SQLi payloads must return 403
###############################################################################

# Tautology bypass attempt
TAUT_CODE=$(curl -so /dev/null -w '%{http_code}' \
  -X POST http://localhost/payroll_app.php \
  --data "username=admin' OR '1'='1&password=x&submit=Login")

if [ "$TAUT_CODE" != "403" ]; then
    echo "FAIL [PoC]: Tautology SQLi payload returned HTTP $TAUT_CODE — expected 403." >&2
    exit 1
fi
echo "PASS [PoC]: Tautology SQLi payload blocked (HTTP 403)."

# UNION SELECT dump attempt
UNION_CODE=$(curl -so /dev/null -w '%{http_code}' \
  -X POST http://localhost/payroll_app.php \
  --data "username=' UNION SELECT 1,2,3--&password=x&submit=Login")

if [ "$UNION_CODE" != "403" ]; then
    echo "FAIL [PoC]: UNION SELECT payload returned HTTP $UNION_CODE — expected 403." >&2
    exit 1
fi
echo "PASS [PoC]: UNION SELECT payload blocked (HTTP 403)."

###############################################################################
# Regression Check: Legitimate login must pass through the WAF
###############################################################################

# Fetch a known-good account from the DB
LEGIT_USER=$(mysql -u root payroll -sNe "SELECT username FROM users LIMIT 1;" 2>/dev/null)
LEGIT_PASS=$(mysql -u root payroll -sNe \
  "SELECT password FROM users WHERE username='${LEGIT_USER}' LIMIT 1;" 2>/dev/null)

if [ -z "$LEGIT_USER" ] || [ -z "$LEGIT_PASS" ]; then
    echo "FAIL [Regression]: Could not retrieve a test account from the payroll DB." >&2
    exit 1
fi

LEGIT_CODE=$(curl -so /dev/null -w '%{http_code}' \
  -X POST http://localhost/payroll_app.php \
  --data "username=${LEGIT_USER}&password=${LEGIT_PASS}&submit=Login")

if [ "$LEGIT_CODE" = "403" ]; then
    echo "FAIL [Regression]: Legitimate login for '$LEGIT_USER' was blocked by WAF (HTTP 403) — rules are too broad." >&2
    exit 1
fi
echo "PASS [Regression]: Legitimate login for '$LEGIT_USER' passed through WAF (HTTP $LEGIT_CODE)."

echo "All checks passed."
exit 0
