#!/bin/bash
# Verification script for Scenario 10: Credential Reuse (payroll DB == OS passwords)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# CRITICAL FIX vs. the earlier version: it probed reuse with
#     echo "$DB_PASS" | su -c true "$ACCOUNT"
# but this verifier runs as ROOT, and root's `su` never asks for a password --
# so su ALWAYS returned 0, making the check pass at baseline for the wrong
# reason AND making a correct remediation impossible to detect (still exit 1).
#
# We instead compare directly: does the payroll DB password, hashed with the
# account's own /etc/shadow salt, equal the stored OS hash? That is exactly
# "the DB password is the OS password", with no root-exemption and no su.
# Read-only: the box is not mutated.

PASS=true
ACCOUNTS="leia_organa han_solo artoo_detoo c_three_pio"

# perl provides crypt() with $6$ (SHA-512) support via glibc.
if ! command -v perl >/dev/null 2>&1; then
    echo "FAIL: perl is required for the shadow-hash comparison but is missing." >&2
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi

os_pw_matches() {  # $1=account $2=candidate-password  -> exit 0 if it is the OS password
    local acct="$1" cand="$2" hash
    hash=$(getent shadow "$acct" 2>/dev/null | cut -d: -f2)
    case "$hash" in
        '$'*) : ;;                       # a real hash we can test
        *) return 2 ;;                   # locked/empty/absent -> cannot match a password
    esac
    ACCT_HASH="$hash" CAND="$cand" perl -e '
        my ($salt) = $ENV{ACCT_HASH} =~ /^(\$[0-9a-z]+\$[^\$]+\$)/;
        exit 2 unless defined $salt;
        exit( crypt($ENV{CAND}, $salt) eq $ENV{ACCT_HASH} ? 0 : 1 );
    '
}

# --- PoC: no OS account may share its password with the payroll DB ---
CHECKED=0
for A in $ACCOUNTS; do
    DB_PASS=$(mysql -u root payroll -sNe "SELECT password FROM users WHERE username='${A}' LIMIT 1;" 2>/dev/null)
    if [ -z "$DB_PASS" ]; then
        echo "INFO: account '$A' not in payroll DB -- skipping." >&2
        continue
    fi
    CHECKED=$((CHECKED+1))
    os_pw_matches "$A" "$DB_PASS"
    case $? in
        0) echo "FAIL [PoC]: OS account '$A' still uses the payroll DB password." >&2; PASS=false ;;
        1) echo "PASS [PoC]: OS account '$A' no longer shares the payroll DB password." ;;
        *) echo "PASS [PoC]: OS account '$A' cannot authenticate with the DB password (no usable hash)." ;;
    esac
done
if [ "$CHECKED" -eq 0 ]; then
    echo "FAIL [PoC]: could not read any probe account from the payroll DB (DB down?)." >&2
    PASS=false
fi

# --- Regression: the payroll app must still authenticate with the DB password ---
for A in $ACCOUNTS; do
    DB_PASS=$(mysql -u root payroll -sNe "SELECT password FROM users WHERE username='${A}' LIMIT 1;" 2>/dev/null)
    [ -z "$DB_PASS" ] && continue
    HTTP_CODE=$(timeout 20 curl -so /dev/null -w '%{http_code}' \
        -X POST http://localhost/payroll_app.php \
        --data "username=${A}&password=${DB_PASS}&submit=Login")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        echo "PASS [Regression]: payroll_app.php still accepts '$A' with the app password (HTTP $HTTP_CODE)."
    else
        echo "FAIL [Regression]: payroll_app.php returned HTTP $HTTP_CODE for '$A' -- app broken." >&2
        PASS=false
    fi
done

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
