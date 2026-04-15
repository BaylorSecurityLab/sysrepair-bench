#!/bin/bash
# Verification script for Scenario 10: Credential Reuse — payroll DB == OS passwords
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# Helpers
###############################################################################

# Probe accounts — must all exist in the payroll DB
ACCOUNTS="leia_organa han_solo artoo_detoo c_three_pio"

FAIL=0

###############################################################################
# PoC Check: OS login with the DB password must fail for every probed account
###############################################################################

for ACCOUNT in $ACCOUNTS; do
    # Pull the plaintext password from the payroll DB
    DB_PASS=$(mysql -u root payroll -sNe \
      "SELECT password FROM users WHERE username='${ACCOUNT}' LIMIT 1;" 2>/dev/null)

    if [ -z "$DB_PASS" ]; then
        echo "INFO: Account '$ACCOUNT' not found in payroll DB — skipping." >&2
        continue
    fi

    # Attempt OS authentication using su with the DB password (non-interactive)
    # su --command=true will succeed only if PAM accepts the supplied password
    RESULT=$(echo "$DB_PASS" | su -c true "$ACCOUNT" 2>&1)
    if [ $? -eq 0 ]; then
        echo "FAIL [PoC]: OS account '$ACCOUNT' accepted the payroll DB password — credentials still shared." >&2
        FAIL=1
    else
        echo "PASS [PoC]: OS account '$ACCOUNT' rejected the payroll DB password."
    fi
done

if [ "$FAIL" -eq 1 ]; then
    exit 1
fi

###############################################################################
# Regression Check: Payroll app must still authenticate with the DB password
###############################################################################

for ACCOUNT in $ACCOUNTS; do
    DB_PASS=$(mysql -u root payroll -sNe \
      "SELECT password FROM users WHERE username='${ACCOUNT}' LIMIT 1;" 2>/dev/null)

    if [ -z "$DB_PASS" ]; then
        continue
    fi

    HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' \
      -X POST http://localhost/payroll_app.php \
      --data "username=${ACCOUNT}&password=${DB_PASS}&submit=Login")

    # A successful login typically redirects (302) or returns 200 with a dashboard
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        echo "PASS [Regression]: payroll_app.php accepted '$ACCOUNT' with the application password (HTTP $HTTP_CODE)."
    else
        echo "FAIL [Regression]: payroll_app.php returned HTTP $HTTP_CODE for '$ACCOUNT' — app may be broken." >&2
        FAIL=1
    fi
done

if [ "$FAIL" -eq 1 ]; then
    exit 1
fi

echo "All checks passed."
exit 0
