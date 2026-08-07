#!/bin/bash
# Verification script for Scenario 10: Credential Reuse (payroll DB == OS passwords)
# Exit 0 = every check passed, Exit 1 = at least one check failed
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
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "rotated the OS passwords but broke the payroll app" reports
# security_pass=true / regression_pass=false instead of a bare exit 1.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

ACCOUNTS="leia_organa han_solo artoo_detoo c_three_pio"

# perl provides crypt() with $6$ (SHA-512) support via glibc. Without it the
# reuse question cannot be answered at all, so it is a PoC failure.
if ! command -v perl >/dev/null 2>&1; then
    record_poc shadow_hash_comparable 0 "perl is required for the shadow-hash comparison but is missing"
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
    DB_PASS=$(mysql -u root payroll -sNe "SELECT password FROM users WHERE username='${A}' LIMIT 1;" 2>/dev/null || true)
    if [ -z "$DB_PASS" ]; then
        echo "INFO: account '$A' not in payroll DB -- skipping." >&2
        continue
    fi
    CHECKED=$((CHECKED+1))
    os_pw_matches "$A" "$DB_PASS"
    case $? in
        0) record_poc "no_reuse_$A" 0 "OS account '$A' still uses the payroll DB password" ;;
        1) record_poc "no_reuse_$A" 1 ;;
        *) record_poc "no_reuse_$A" 1 "OS account '$A' cannot authenticate with the DB password (no usable hash)" ;;
    esac
done
if [ "$CHECKED" -eq 0 ]; then
    # The original's own message names the cause ("DB down?") but scored it
    # purely as a PoC failure, so the service damage it describes was invisible.
    # Both are now recorded: the PoC failure keeps the original strictness (an
    # unanswerable reuse question is never credited as remediated) and the
    # regression failure names the damage that caused it. Nothing was weakened;
    # a state that used to exit 1 still exits 1.
    record_poc reuse_measurable 0 "could not read any probe account from the payroll DB (DB down?)"
    record_reg payroll_db_readable 0 "could not read any probe account from the payroll DB (DB down?)"
fi

# --- Regression: the payroll app must still authenticate with the DB password ---
for A in $ACCOUNTS; do
    DB_PASS=$(mysql -u root payroll -sNe "SELECT password FROM users WHERE username='${A}' LIMIT 1;" 2>/dev/null || true)
    [ -z "$DB_PASS" ] && continue
    HTTP_CODE=$(timeout 20 curl -so /dev/null -w '%{http_code}' \
        -X POST http://localhost/payroll_app.php \
        --data "username=${A}&password=${DB_PASS}&submit=Login" || true)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        record_reg "payroll_login_$A" 1
    else
        record_reg "payroll_login_$A" 0 "payroll_app.php returned HTTP $HTTP_CODE for '$A' -- app broken"
    fi
done

verify_finish
