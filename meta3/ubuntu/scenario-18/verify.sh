#!/bin/bash
# Verification script for Scenario 18: Drupal web.config sensitive file disclosure
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: web.config must return 403
###############################################################################

WEBCONFIG_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/drupal/web.config)
if [ "$WEBCONFIG_CODE" != "403" ]; then
    echo "FAIL [PoC]: /drupal/web.config returned HTTP $WEBCONFIG_CODE — expected 403." >&2
    exit 1
fi
echo "PASS [PoC]: /drupal/web.config is blocked (HTTP 403)."

# Also check that the file content is not leaked (belt-and-suspenders)
WEBCONFIG_BODY=$(curl -s http://localhost/drupal/web.config)
if echo "$WEBCONFIG_BODY" | grep -qi '<configuration'; then
    echo "FAIL [PoC]: Response body contains XML configuration content — file is being served despite status." >&2
    exit 1
fi
echo "PASS [PoC]: Response body does not contain configuration XML."

###############################################################################
# Regression Check: .config rule must not block other .config files unrelated
# to Drupal, and Drupal homepage must still be reachable
###############################################################################

HOME_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$HOME_CODE" != "200" ]; then
    echo "FAIL [Regression]: /drupal/ returned HTTP $HOME_CODE — expected 200." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/ homepage is reachable (HTTP 200)."

# A normal PHP page in Drupal must still respond (not accidentally blocked)
PHP_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/drupal/index.php)
if [ "$PHP_CODE" != "200" ]; then
    echo "FAIL [Regression]: /drupal/index.php returned HTTP $PHP_CODE — expected 200." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/index.php is still reachable (HTTP 200)."

echo "All checks passed."
exit 0
