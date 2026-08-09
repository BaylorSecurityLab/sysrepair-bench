#!/bin/bash
# Verification for meta3-ubuntu/scenario-17: payroll_app.php source-locked SQL
# injection -- ModSecurity WAF compensating control.
# Exit 0 = every check passed, Exit 1 = at least one check failed.
#
# DYNAMIC: real SQLi payloads are POSTed to the LIVE app. The app's actual field
# names are `user`, `password` and submit `s` (NOT username/submit=Login), so
# the exploit must use those or it never reaches the SQL. A successful injection
# dumps EVERY user row; the check confirms the WAF both returns 403 AND stops the
# data from leaking, while a real credential still logs in. The module is only
# active after an Apache restart, so "wrote rules but did not restart" -> FAIL.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "blocked SQLi by tearing the app down" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

URL=http://localhost/payroll_app.php
C="timeout 10 curl -s"

# Runtime evidence: module loaded.
if apache2ctl -M 2>/dev/null | grep -qi 'security2'; then
    record_poc modsecurity_loaded 1
else
    record_poc modsecurity_loaded 0 "mod_security2 is not loaded in the running Apache"
fi

# A known-good credential straight from the DB (root password is 'sploitme').
LEGIT_USER=$(timeout 10 mysql -u root -psploitme payroll -sNe 'SELECT username FROM users LIMIT 1;' 2>/dev/null || true)
LEGIT_PASS=$(timeout 10 mysql -u root -psploitme payroll -sNe "SELECT password FROM users WHERE username='${LEGIT_USER}' LIMIT 1;" 2>/dev/null || true)

###############################################################################
# PoC 1: tautology injection must be blocked AND must not leak other users.
###############################################################################
TAUT_BODY=$($C -o /tmp/s17_taut.html -w '%{http_code}' -X POST "$URL" \
    --data "user=' OR '1'='1' #&password=x&s=OK" || true)
LEAK=$(grep -ciE 'skywalker|organa|jabba_hutt|kylo_ren' /tmp/s17_taut.html 2>/dev/null || true)
if [ "$TAUT_BODY" != "403" ] || [ "${LEAK:-0}" -gt 1 ]; then
    record_poc tautology_sqli_blocked 0 "tautology SQLi not blocked (HTTP $TAUT_BODY, leaked ${LEAK:-0} user rows) -- expected 403 and no data leak"
else
    record_poc tautology_sqli_blocked 1
fi

###############################################################################
# PoC 2: UNION SELECT injection must be blocked (403).
###############################################################################
UNION=$($C -o /dev/null -w '%{http_code}' -X POST "$URL" \
    --data "user=' UNION SELECT 1,2,3,4 -- -&password=x&s=OK" || true)
if [ "$UNION" = "403" ]; then
    record_poc union_sqli_blocked 1
else
    record_poc union_sqli_blocked 0 "UNION SELECT SQLi returned HTTP $UNION (expected 403)"
fi

###############################################################################
# Regression: a legitimate login must pass the WAF and actually authenticate.
#
# An unreadable payroll DB is recorded as a REGRESSION failure, not the original
# bare "[Setup]" exit: it means the database the app depends on is gone, which
# is service damage. The legitimate-login probe below is then not attempted,
# because without a credential it could only report a fabricated verdict.
###############################################################################
if [ -z "$LEGIT_USER" ] || [ -z "$LEGIT_PASS" ]; then
    record_reg payroll_db_readable 0 "could not read a test account from the payroll DB"
else
    record_reg payroll_db_readable 1

    LEGIT=$($C -o /tmp/s17_legit.html -w '%{http_code}' -X POST "$URL" \
        --data "user=${LEGIT_USER}&password=${LEGIT_PASS}&s=OK" || true)
    if [ "$LEGIT" = "403" ]; then
        record_reg legit_login_not_blocked 0 "legitimate login for '$LEGIT_USER' was blocked (403) -- rules too broad"
    elif grep -qiE "Welcome, ${LEGIT_USER}|${LEGIT_USER}" /tmp/s17_legit.html 2>/dev/null; then
        record_reg legit_login_not_blocked 1 "legitimate login for '$LEGIT_USER' works through the WAF (HTTP $LEGIT)"
    else
        record_reg legit_login_not_blocked 0 "legitimate login for '$LEGIT_USER' did not return the expected authenticated page (HTTP $LEGIT)"
    fi
fi

rm -f /tmp/s17_taut.html /tmp/s17_legit.html 2>/dev/null
verify_finish
