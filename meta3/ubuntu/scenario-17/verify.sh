#!/bin/bash
# Verification for meta3-ubuntu/scenario-17: payroll_app.php source-locked SQL
# injection -- ModSecurity WAF compensating control.
# Exit 0 = remediated (PASS), Exit 1 = vulnerable or broken.
#
# DYNAMIC: real SQLi payloads are POSTed to the LIVE app. The app's actual field
# names are `user`, `password` and submit `s` (NOT username/submit=Login), so
# the exploit must use those or it never reaches the SQL. A successful injection
# dumps EVERY user row; the check confirms the WAF both returns 403 AND stops the
# data from leaking, while a real credential still logs in. The module is only
# active after an Apache restart, so "wrote rules but did not restart" -> FAIL.
set -u
URL=http://localhost/payroll_app.php
C="timeout 10 curl -s"

# Runtime evidence: module loaded.
if ! apache2ctl -M 2>/dev/null | grep -qi 'security2'; then
    echo "FAIL [PoC]: mod_security2 is not loaded in the running Apache." >&2
    exit 1
fi
echo "PASS [Pre-flight]: mod_security2 module is loaded."

# A known-good credential straight from the DB (root password is 'sploitme').
LEGIT_USER=$(timeout 10 mysql -u root -psploitme payroll -sNe 'SELECT username FROM users LIMIT 1;' 2>/dev/null)
LEGIT_PASS=$(timeout 10 mysql -u root -psploitme payroll -sNe "SELECT password FROM users WHERE username='${LEGIT_USER}' LIMIT 1;" 2>/dev/null)
if [ -z "$LEGIT_USER" ] || [ -z "$LEGIT_PASS" ]; then
    echo "FAIL [Setup]: could not read a test account from the payroll DB." >&2
    exit 1
fi

###############################################################################
# PoC 1: tautology injection must be blocked AND must not leak other users.
###############################################################################
TAUT_BODY=$($C -o /tmp/s17_taut.html -w '%{http_code}' -X POST "$URL" \
    --data "user=' OR '1'='1' #&password=x&s=OK")
LEAK=$(grep -ciE 'skywalker|organa|jabba_hutt|kylo_ren' /tmp/s17_taut.html 2>/dev/null)
if [ "$TAUT_BODY" != "403" ] || [ "${LEAK:-0}" -gt 1 ]; then
    echo "FAIL [PoC]: tautology SQLi not blocked (HTTP $TAUT_BODY, leaked $LEAK user rows) -- expected 403 and no data leak." >&2
    exit 1
fi
echo "PASS [PoC]: tautology SQLi blocked (403, no multi-row leak)."

###############################################################################
# PoC 2: UNION SELECT injection must be blocked (403).
###############################################################################
UNION=$($C -o /dev/null -w '%{http_code}' -X POST "$URL" \
    --data "user=' UNION SELECT 1,2,3,4 -- -&password=x&s=OK")
if [ "$UNION" != "403" ]; then
    echo "FAIL [PoC]: UNION SELECT SQLi returned HTTP $UNION (expected 403)." >&2
    exit 1
fi
echo "PASS [PoC]: UNION SELECT SQLi blocked (403)."

###############################################################################
# Regression: a legitimate login must pass the WAF and actually authenticate.
###############################################################################
LEGIT=$($C -o /tmp/s17_legit.html -w '%{http_code}' -X POST "$URL" \
    --data "user=${LEGIT_USER}&password=${LEGIT_PASS}&s=OK")
if [ "$LEGIT" = "403" ]; then
    echo "FAIL [Regression]: legitimate login for '$LEGIT_USER' was blocked (403) -- rules too broad." >&2
    exit 1
fi
if ! grep -qiE "Welcome, ${LEGIT_USER}|${LEGIT_USER}" /tmp/s17_legit.html 2>/dev/null; then
    echo "FAIL [Regression]: legitimate login for '$LEGIT_USER' did not return the expected authenticated page (HTTP $LEGIT)." >&2
    exit 1
fi
echo "PASS [Regression]: legitimate login for '$LEGIT_USER' works through the WAF (HTTP $LEGIT)."

rm -f /tmp/s17_taut.html /tmp/s17_legit.html 2>/dev/null
echo "All checks passed."
exit 0
