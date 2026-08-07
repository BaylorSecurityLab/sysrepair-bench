#!/bin/bash
# Verification: Scenario 08 - WordPress weak passwords / phpass hashes (CWE-916)
# VulnHub Source: DC-2
#
# PoC checks:        no phpass hashes; hashes are a strong modern format AND do
#                    not verify any common weak password
# Regression checks: MariaDB answers and the user rows still exist
#
# Exit 0 = every check passed          (remediated, credential store intact)
# Exit 1 = at least one check failed
#
# Dynamic evidence: we query the LIVE credential store and then actually run
# php password_verify() of a weak-password dictionary against each stored hash -
# so "just re-hash the same weak password with bcrypt" is caught. The image CMD
# boots MariaDB (see .preserve-cmd); verify.sh must NOT start it.
#
# Two-component protocol: nothing aborts early. All evidence here lives in the
# database, so when the store is unreachable the PoC is recorded as FAILED
# ("cannot prove the hashes are strong") rather than credited - destroying the
# database must never read as fixing the passwords. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

if ! command -v mysql >/dev/null 2>&1; then
    record_reg mariadb_answers_queries 0 "mysql client missing"
    record_poc wp_hashes_strong 0 "mysql client missing - cannot read the credential store"
    verify_finish
fi

# --- Regression: DB up and rows intact ---
if timeout 15 mysql -N -e "SELECT 1;" >/dev/null 2>&1; then
    record_reg mariadb_answers_queries 1
else
    record_reg mariadb_answers_queries 0 "MariaDB is not answering (server down?)"
fi

ROWS=$(timeout 15 mysql -N -e "SELECT COUNT(*) FROM wordpress.wp_users;" 2>/dev/null)
echo "  wp_users row count: ${ROWS:-0}"
if [ "${ROWS:-0}" -lt 2 ] 2>/dev/null; then
    record_reg wp_user_rows_intact 0 "expected the admin+editor rows to still exist (found ${ROWS:-0})"
else
    record_reg wp_user_rows_intact 1
fi

# Weak-password dictionary the stored hashes must NOT verify against.
WEAK="admin password 123456 admin123 letmein editor changeme wordpress admin@123 password1 12345678 qwerty"

USERS_SEEN=0

# Iterate every user's stored hash.  A heredoc (not a pipe) feeds the loop, so
# the counters below live in THIS shell and survive the loop.
while IFS=$'\t' read -r LOGIN HASH; do
    [ -n "$LOGIN" ] || continue
    USERS_SEEN=$((USERS_SEEN + 1))
    SAFE_LOGIN=$(printf '%s' "$LOGIN" | tr -c 'A-Za-z0-9' '_')
    echo "  user '$LOGIN' hash prefix: $(printf '%s' "$HASH" | cut -c1-4)"

    # --- PoC 1: no legacy phpass/portable hashes ($P$ or $H$) ---
    case "$HASH" in
        '$P$'*|'$H$'*)
            record_poc "hash_not_phpass_${SAFE_LOGIN}" 0 "user '$LOGIN' still uses a phpass hash - crackable"
            continue
            ;;
    esac
    record_poc "hash_not_phpass_${SAFE_LOGIN}" 1

    # --- PoC 2: must be a recognised strong algorithm (bcrypt/argon2) ---
    case "$HASH" in
        '$2y$'*|'$2a$'*|'$2b$'*|'$argon2i$'*|'$argon2id$'*)
            record_poc "hash_strong_format_${SAFE_LOGIN}" 1
            ;;
        *)
            record_poc "hash_strong_format_${SAFE_LOGIN}" 0 "user '$LOGIN' hash is not a strong modern format: $(printf '%s' "$HASH" | cut -c1-6)"
            continue
            ;;
    esac

    # --- PoC 3: the strong hash must NOT verify any weak password ---
    HIT=$(timeout 20 php -r '
        $hash=$argv[1];
        foreach (array_slice($argv,2) as $pw) {
            if (password_verify($pw,$hash)) { echo $pw; exit; }
        }' "$HASH" $WEAK 2>/dev/null)
    if [ -n "$HIT" ]; then
        record_poc "hash_resists_dictionary_${SAFE_LOGIN}" 0 "user '$LOGIN' password is still weak - hash verifies '$HIT'"
    else
        record_poc "hash_resists_dictionary_${SAFE_LOGIN}" 1
    fi
done <<EOF
$(timeout 15 mysql -N -e "SELECT user_login, user_pass FROM wordpress.wp_users;" 2>/dev/null)
EOF

if [ "$USERS_SEEN" -eq 0 ]; then
    record_poc wp_hashes_strong 0 "could not enumerate wp_users hashes - the credential store is unreachable, so the weak-hash finding cannot be shown closed"
fi

verify_finish
