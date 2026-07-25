#!/bin/bash
# Verification for meta3-ubuntu/scenario-18: Drupal web.config sensitive file
# disclosure over Apache. Exit 0 = remediated (PASS), Exit 1 = vulnerable/broken.
#
# DYNAMIC: the file is requested from the LIVE Apache. Apache reads the deny
# directive only at (re)start, so "wrote the config but did not reload" leaves
# web.config served -> FAIL.
set -u
C="timeout 10 curl -s"

###############################################################################
# PoC: /drupal/web.config must be denied (403) and must not leak its XML body.
###############################################################################
CODE=$($C -o /dev/null -w '%{http_code}' http://localhost/drupal/web.config)
if [ "$CODE" != "403" ]; then
    echo "FAIL [PoC]: /drupal/web.config returned HTTP $CODE (expected 403)." >&2
    exit 1
fi
echo "PASS [PoC]: /drupal/web.config is blocked (403)."

BODY=$($C http://localhost/drupal/web.config)
if echo "$BODY" | grep -qi '<configuration'; then
    echo "FAIL [PoC]: response body still contains the web.config XML -- file is being served." >&2
    exit 1
fi
echo "PASS [PoC]: response body does not contain the configuration XML."

###############################################################################
# Regression: Drupal must still serve normally.
###############################################################################
HOME=$($C -o /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$HOME" != "200" ]; then
    echo "FAIL [Regression]: /drupal/ returned HTTP $HOME (expected 200)." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/ homepage reachable (200)."

PHP=$($C -o /dev/null -w '%{http_code}' http://localhost/drupal/index.php)
if [ "$PHP" != "200" ]; then
    echo "FAIL [Regression]: /drupal/index.php returned HTTP $PHP (expected 200 -- rule too broad)." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/index.php still reachable (200)."

echo "All checks passed."
exit 0
