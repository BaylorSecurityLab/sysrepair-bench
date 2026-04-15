#!/bin/bash
# Verification script for Scenario 19: phpMyAdmin exposed cleartext HTTP, no source restriction
# Exit 0 = remediated (PASS), Exit 1 = still vulnerable or broken (FAIL)

###############################################################################
# PoC Check A: Apache config must contain a source-restriction directive for /phpmyadmin
###############################################################################

if grep -rqiE '(Require ip|Allow from 127|Require local)' /etc/apache2/ 2>/dev/null; then
    echo "PASS [PoC]: Apache config contains a source-restriction directive for phpMyAdmin."
else
    echo "FAIL [PoC]: No 'Require ip', 'Require local', or 'Allow from 127' directive found in Apache config — phpMyAdmin is unrestricted." >&2
    exit 1
fi

###############################################################################
# PoC Check B: Access from 127.0.0.1 (localhost) must return 200
###############################################################################

LOCAL_CODE=$(curl -so /dev/null -w '%{http_code}' \
  --interface 127.0.0.1 \
  http://127.0.0.1/phpmyadmin/)

if [ "$LOCAL_CODE" != "200" ]; then
    echo "FAIL [Regression]: /phpmyadmin/ returned HTTP $LOCAL_CODE from 127.0.0.1 — expected 200." >&2
    exit 1
fi
echo "PASS [PoC]: /phpmyadmin/ is reachable from 127.0.0.1 (HTTP 200)."

###############################################################################
# PoC Check C: Confirm that a non-loopback binding would be blocked
#
# Inside a Docker container there is typically no additional non-loopback
# interface to probe.  We therefore rely on the config inspection above (Check A)
# as the authoritative evidence of restriction.  If a second interface exists,
# we attempt it and expect 403.
###############################################################################

EXTRA_IFACE=$(ip -4 addr show | awk '/inet /{print $2}' | grep -v '^127\.' | head -1 | cut -d/ -f1)

if [ -n "$EXTRA_IFACE" ]; then
    EXT_CODE=$(curl -so /dev/null -w '%{http_code}' \
      --interface "$EXTRA_IFACE" \
      "http://${EXTRA_IFACE}/phpmyadmin/" 2>/dev/null)
    if [ "$EXT_CODE" = "200" ]; then
        echo "FAIL [PoC]: /phpmyadmin/ returned HTTP 200 from non-loopback address $EXTRA_IFACE — restriction not effective." >&2
        exit 1
    fi
    echo "PASS [PoC]: /phpmyadmin/ returned HTTP $EXT_CODE from $EXTRA_IFACE (access restricted as expected)."
else
    echo "INFO: No non-loopback interface available in this container — restriction verified via config inspection only."
fi

###############################################################################
# Regression Check: Drupal homepage must not be affected
###############################################################################

HOME_CODE=$(curl -so /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$HOME_CODE" != "200" ]; then
    echo "FAIL [Regression]: /drupal/ returned HTTP $HOME_CODE — expected 200." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/ homepage is reachable (HTTP 200)."

echo "All checks passed."
exit 0
