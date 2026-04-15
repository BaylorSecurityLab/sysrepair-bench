#!/bin/bash
# Verification script for Scenario 13: Drupal 7.31 pinned — mod_security WAF
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
    echo "FAIL [PoC]: SecRuleEngine is not set to 'On' in /etc/modsecurity/ — WAF is in detection-only mode." >&2
    exit 1
fi
echo "PASS [Pre-flight]: SecRuleEngine is On."

###############################################################################
# PoC Check: Drupalgeddon payload must return 403
###############################################################################

# Payload 1: name-array POST body injection (space-semicolon pattern)
PAYLOAD1_CODE=$(curl -so /dev/null -w '%{http_code}' \
  -X POST 'http://localhost/drupal/?q=node&destination=node' \
  --data 'name[0 ;UPDATE users SET name=pwned WHERE uid=1;#]=foo&pass=foo&form_id=user_login_block')

if [ "$PAYLOAD1_CODE" != "403" ]; then
    echo "FAIL [PoC]: Drupalgeddon name-array payload returned HTTP $PAYLOAD1_CODE — expected 403." >&2
    exit 1
fi
echo "PASS [PoC]: Drupalgeddon name-array payload blocked (HTTP 403)."

# Payload 2: post_render callback registration via query string
PAYLOAD2_CODE=$(curl -so /dev/null -w '%{http_code}' \
  'http://localhost/drupal/?q=node&destination=node&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=id')

if [ "$PAYLOAD2_CODE" != "403" ]; then
    echo "FAIL [PoC]: Drupalgeddon post_render payload returned HTTP $PAYLOAD2_CODE — expected 403." >&2
    exit 1
fi
echo "PASS [PoC]: Drupalgeddon post_render payload blocked (HTTP 403)."

###############################################################################
# Regression Check: Drupal homepage and a legitimate POST must still work
###############################################################################

HOME_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$HOME_CODE" != "200" ]; then
    echo "FAIL [Regression]: /drupal/ returned HTTP $HOME_CODE — expected 200." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/ homepage is reachable (HTTP 200)."

# A legitimate login attempt (wrong password is fine — must not get 403)
LOGIN_CODE=$(curl -so /dev/null -w '%{http_code}' \
  -X POST 'http://localhost/drupal/?q=user&destination=user' \
  --data 'name=admin&pass=wrongpassword&form_id=user_login&op=Log+in')

if [ "$LOGIN_CODE" = "403" ]; then
    echo "FAIL [Regression]: Legitimate Drupal login POST was blocked by WAF (HTTP 403) — rules are too broad." >&2
    exit 1
fi
echo "PASS [Regression]: Legitimate Drupal login POST passed through WAF (HTTP $LOGIN_CODE)."

echo "All checks passed."
exit 0
