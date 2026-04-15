#!/bin/bash
# Verification script for Scenario 06: Drupalgeddon CVE-2014-3704
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Drupalgeddon SQL injection payload must not alter data
###############################################################################

# Capture the uid=1 user name before the injection attempt
BEFORE=$(mysql -u root drupal -sNe "SELECT name FROM users WHERE uid=1;" 2>/dev/null)
if [ -z "$BEFORE" ]; then
    echo "FAIL [PoC]: Could not query Drupal users table — database may not be initialised." >&2
    exit 1
fi

# Send the Drupalgeddon payload attempting to rename uid=1 to 'pwned'
curl -s -X POST \
  'http://localhost/drupal/?q=node&destination=node' \
  --data 'name[0%20;UPDATE%20users%20SET%20name%3dpwned%20WHERE%20uid%3d1;%23]=foo&pass=foo&form_id=user_login_block' \
  -o /dev/null

# Query again and compare
AFTER=$(mysql -u root drupal -sNe "SELECT name FROM users WHERE uid=1;" 2>/dev/null)

if [ "$AFTER" = "pwned" ]; then
    echo "FAIL [PoC]: Drupalgeddon SQL injection succeeded — uid=1 user renamed to 'pwned'." >&2
    exit 1
fi
echo "PASS [PoC]: Drupalgeddon payload did not alter database (uid=1 name='$AFTER')."

###############################################################################
# Patch version check: database.inc must be from 7.32+
###############################################################################

CHANGELOG="/var/www/html/drupal/CHANGELOG.txt"
if grep -qE 'Drupal 7\.(3[2-9]|[4-9][0-9])' "$CHANGELOG" 2>/dev/null; then
    echo "PASS [PoC]: Drupal CHANGELOG.txt confirms 7.32 or later."
else
    echo "FAIL [PoC]: CHANGELOG.txt does not indicate Drupal >= 7.32 — patch may not be applied." >&2
    exit 1
fi

###############################################################################
# Regression Check: Drupal homepage must still return 200
###############################################################################

HOME_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$HOME_CODE" != "200" ]; then
    echo "FAIL [Regression]: /drupal/ returned HTTP $HOME_CODE — expected 200." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/ homepage is reachable (HTTP 200)."

echo "All checks passed."
exit 0
