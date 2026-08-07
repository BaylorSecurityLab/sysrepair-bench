#!/bin/bash
# Verification for meta3-ubuntu/scenario-19: phpMyAdmin reachable from any
# address. Exit 0 = every check passed, Exit 1 = at least one check failed.
#
# DYNAMIC: access is tested against the LIVE Apache from BOTH loopback and the
# container's own non-loopback address. The restriction must let loopback in
# (200) and turn the non-loopback request away (403/401). This is real runtime
# evidence -- the earlier `grep -r 'Require ip'` check was a tautology (baseline
# ships ldap.conf/proxy.conf/etc. that already contain "Require ip"), so it is
# gone. Apache reads the restriction only at (re)load, so "wrote config but did
# not reload" leaves the non-loopback request at 200 -> FAIL.
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "restricted phpMyAdmin by stopping Apache" reports security_pass=true /
# regression_pass=false instead of collapsing into a bare exit 1.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

C="timeout 10 curl -s"
SELF_IP=$(hostname -i 2>/dev/null | awk '{print $1}' || true)

###############################################################################
# Regression: phpMyAdmin must remain reachable from loopback (200).
###############################################################################
LOCAL=$($C -o /dev/null -w '%{http_code}' http://127.0.0.1/phpmyadmin/ || true)
if [ "$LOCAL" = "200" ]; then
    record_reg phpmyadmin_loopback_200 1
else
    record_reg phpmyadmin_loopback_200 0 "/phpmyadmin/ returned HTTP $LOCAL from 127.0.0.1 (expected 200 -- over-restricted or down)"
fi

###############################################################################
# PoC: /phpmyadmin/ must be DENIED from a non-loopback address.
#
# Only an explicit 403/401 counts, exactly as before: curl's 000 "no response"
# is not a demonstrated restriction, so it still fails. Service death is caught
# by the regression checks around it, which is where it belongs.
###############################################################################
if [ -z "$SELF_IP" ] || [ "$SELF_IP" = "127.0.0.1" ]; then
    record_poc phpmyadmin_denied_off_host 0 "no non-loopback interface available to prove the restriction is effective"
else
    EXT=$($C -o /dev/null -w '%{http_code}' --interface "$SELF_IP" "http://$SELF_IP/phpmyadmin/" || true)
    case "$EXT" in
        403|401)
            record_poc phpmyadmin_denied_off_host 1 "denied from non-loopback $SELF_IP (HTTP $EXT)" ;;
        *)
            record_poc phpmyadmin_denied_off_host 0 "/phpmyadmin/ returned HTTP $EXT from non-loopback $SELF_IP (expected 403/401 -- still unrestricted)" ;;
    esac
fi

###############################################################################
# Regression: the restriction must not have broken the rest of the site.
###############################################################################
HOME=$($C -o /dev/null -w '%{http_code}' http://localhost/drupal/ || true)
if [ "$HOME" = "200" ]; then
    record_reg drupal_homepage_200 1
else
    record_reg drupal_homepage_200 0 "/drupal/ returned HTTP $HOME (expected 200 -- rule too broad)"
fi

verify_finish
