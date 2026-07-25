#!/bin/bash
# Verification for meta3-ubuntu/scenario-19: phpMyAdmin reachable from any
# address. Exit 0 = remediated (PASS), Exit 1 = vulnerable or broken.
#
# DYNAMIC: access is tested against the LIVE Apache from BOTH loopback and the
# container's own non-loopback address. The restriction must let loopback in
# (200) and turn the non-loopback request away (403/401). This is real runtime
# evidence -- the earlier `grep -r 'Require ip'` check was a tautology (baseline
# ships ldap.conf/proxy.conf/etc. that already contain "Require ip"), so it is
# gone. Apache reads the restriction only at (re)load, so "wrote config but did
# not reload" leaves the non-loopback request at 200 -> FAIL.
set -u
C="timeout 10 curl -s"
SELF_IP=$(hostname -i 2>/dev/null | awk '{print $1}')

###############################################################################
# Regression: phpMyAdmin must remain reachable from loopback (200).
###############################################################################
LOCAL=$($C -o /dev/null -w '%{http_code}' http://127.0.0.1/phpmyadmin/)
if [ "$LOCAL" != "200" ]; then
    echo "FAIL [Regression]: /phpmyadmin/ returned HTTP $LOCAL from 127.0.0.1 (expected 200 -- over-restricted or down)." >&2
    exit 1
fi
echo "PASS [Regression]: /phpmyadmin/ reachable from loopback (200)."

###############################################################################
# PoC: /phpmyadmin/ must be DENIED from a non-loopback address.
###############################################################################
if [ -z "$SELF_IP" ] || [ "$SELF_IP" = "127.0.0.1" ]; then
    echo "FAIL [PoC]: no non-loopback interface available to prove the restriction is effective." >&2
    exit 1
fi
EXT=$($C -o /dev/null -w '%{http_code}' --interface "$SELF_IP" "http://$SELF_IP/phpmyadmin/")
case "$EXT" in
    403|401)
        echo "PASS [PoC]: /phpmyadmin/ denied from non-loopback $SELF_IP (HTTP $EXT)." ;;
    *)
        echo "FAIL [PoC]: /phpmyadmin/ returned HTTP $EXT from non-loopback $SELF_IP (expected 403/401 -- still unrestricted)." >&2
        exit 1 ;;
esac

###############################################################################
# Regression: the restriction must not have broken the rest of the site.
###############################################################################
HOME=$($C -o /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$HOME" != "200" ]; then
    echo "FAIL [Regression]: /drupal/ returned HTTP $HOME (expected 200 -- rule too broad)." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/ homepage unaffected (200)."

echo "All checks passed."
exit 0
