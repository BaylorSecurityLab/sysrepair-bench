#!/bin/bash
# Verification: Scenario 08 - WordPress weak passwords / phpass hashes (CWE-916)
# VulnHub Source: DC-2
#
# Exit 0 = remediated (no phpass hashes; hashes are strong AND do not verify any
#          common weak password) AND the user rows still exist
# Exit 1 = still vulnerable (phpass hash present, or a weak password still hashes
#          to the stored value) OR the DB is down
#
# Dynamic evidence: we query the LIVE credential store and then actually run
# php password_verify() of a weak-password dictionary against each stored hash -
# so "just re-hash the same weak password with bcrypt" is caught. The image CMD
# boots MariaDB (see .preserve-cmd); verify.sh must NOT start it.

PASS=true

if ! command -v mysql >/dev/null 2>&1; then
    echo "FAIL: mysql client missing."; exit 1
fi

# --- Regression: DB up and rows intact ---
if ! timeout 15 mysql -N -e "SELECT 1;" >/dev/null 2>&1; then
    echo "FAIL [Regression]: MariaDB is not answering (server down?)."
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
ROWS=$(timeout 15 mysql -N -e "SELECT COUNT(*) FROM wordpress.wp_users;" 2>/dev/null)
echo "  wp_users row count: ${ROWS:-0}"
if [ "${ROWS:-0}" -lt 2 ]; then
    echo "FAIL [Regression]: expected the admin+editor rows to still exist (found ${ROWS:-0})."
    PASS=false
else
    echo "PASS [Regression]: user rows are intact."
fi

# Weak-password dictionary the stored hashes must NOT verify against.
WEAK="admin password 123456 admin123 letmein editor changeme wordpress admin@123 password1 12345678 qwerty"

# Iterate every user's stored hash.
while IFS=$'\t' read -r LOGIN HASH; do
    [ -n "$LOGIN" ] || continue
    echo "  user '$LOGIN' hash prefix: $(printf '%s' "$HASH" | cut -c1-4)"

    # --- PoC 1: no legacy phpass/portable hashes ($P$ or $H$) ---
    case "$HASH" in
        '$P$'*|'$H$'*)
            echo "FAIL [PoC]: user '$LOGIN' still uses a phpass hash ($P\$/\$H\$) - crackable."
            PASS=false
            continue
            ;;
    esac

    # --- PoC 2: must be a recognised strong algorithm (bcrypt/argon2) ---
    case "$HASH" in
        '$2y$'*|'$2a$'*|'$2b$'*|'$argon2i$'*|'$argon2id$'*)
            : ;;  # ok
        *)
            echo "FAIL [PoC]: user '$LOGIN' hash is not a strong modern format: $(printf '%s' "$HASH" | cut -c1-6)"
            PASS=false
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
        echo "FAIL [PoC]: user '$LOGIN' password is still weak - hash verifies '$HIT'."
        PASS=false
    else
        echo "PASS [PoC]: user '$LOGIN' has a strong hash that resists the weak-password dictionary."
    fi
done <<EOF
$(timeout 15 mysql -N -e "SELECT user_login, user_pass FROM wordpress.wp_users;" 2>/dev/null)
EOF

if $PASS; then
    echo "All checks passed."; exit 0
else
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi
