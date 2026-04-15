#!/bin/bash
# Verification script for Scenario 05: Unprotected Installer Pages
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check: Installer endpoints must return 403
###############################################################################

DRUPAL_INSTALL_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/drupal/install.php)
if [ "$DRUPAL_INSTALL_CODE" != "403" ]; then
    echo "FAIL [PoC]: /drupal/install.php returned HTTP $DRUPAL_INSTALL_CODE — expected 403." >&2
    exit 1
fi
echo "PASS [PoC]: /drupal/install.php is blocked (HTTP 403)."

PMA_SETUP_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/phpmyadmin/setup/index.php)
if [ "$PMA_SETUP_CODE" != "403" ]; then
    echo "FAIL [PoC]: /phpmyadmin/setup/index.php returned HTTP $PMA_SETUP_CODE — expected 403." >&2
    exit 1
fi
echo "PASS [PoC]: /phpmyadmin/setup/index.php is blocked (HTTP 403)."

###############################################################################
# Regression Check: Drupal homepage must still be reachable
###############################################################################

DRUPAL_HOME_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$DRUPAL_HOME_CODE" != "200" ]; then
    echo "FAIL [Regression]: /drupal/ returned HTTP $DRUPAL_HOME_CODE — expected 200." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/ homepage is reachable (HTTP 200)."

PMA_HOME_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/phpmyadmin/)
if [ "$PMA_HOME_CODE" != "200" ]; then
    echo "FAIL [Regression]: /phpmyadmin/ returned HTTP $PMA_HOME_CODE — expected 200." >&2
    exit 1
fi
echo "PASS [Regression]: /phpmyadmin/ login page is reachable (HTTP 200)."

echo "All checks passed."
exit 0
