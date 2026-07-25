#!/bin/bash
# Verification for meta3-ubuntu/scenario-13: Drupal 7.5 (Drupalgeddon,
# CVE-2014-3704) pinned -- ModSecurity WAF compensating control.
# Exit 0 = remediated (PASS), Exit 1 = vulnerable or broken.
#
# DYNAMIC: the two Drupalgeddon payloads are fired at the LIVE Apache. The WAF
# module is only attached after Apache is restarted, so "wrote the rules but did
# not restart Apache" correctly FAILS (payload is not blocked -> not 403).
set -u
C="timeout 10 curl -sg"   # -g/--globoff: payload URLs contain [ ] which curl would treat as globs

# Runtime evidence #1: the module must actually be loaded into the running server.
if ! apache2ctl -M 2>/dev/null | grep -qi 'security2'; then
    echo "FAIL [PoC]: mod_security2 is not loaded in the running Apache." >&2
    exit 1
fi
echo "PASS [Pre-flight]: mod_security2 module is loaded."

###############################################################################
# PoC: Drupalgeddon payloads must be blocked (HTTP 403) by the live WAF.
###############################################################################
# Read-only payload body of the SAME shape the WAF matches ("name[0 ;...").
# The WAF keys on the shape, not the SQL effect, so a benign SELECT proves the
# block without risking a destructive write in the not-yet-protected path.
P1=$($C -o /dev/null -w '%{http_code}' \
  -X POST 'http://localhost/drupal/?q=node&destination=node' \
  --data 'name[0 ;SELECT 1;#]=foo&pass=foo&form_id=user_login_block')
if [ "$P1" != "403" ]; then
    echo "FAIL [PoC]: Drupalgeddon name-array payload returned HTTP $P1 (expected 403 from the WAF)." >&2
    exit 1
fi
echo "PASS [PoC]: name-array Drupalgeddon payload blocked (403)."

P2=$($C -o /dev/null -w '%{http_code}' \
  'http://localhost/drupal/?q=node&destination=node&name[%23post_render][]=passthru&name[%23type]=markup&name[%23markup]=id')
if [ "$P2" != "403" ]; then
    echo "FAIL [PoC]: Drupalgeddon post_render payload returned HTTP $P2 (expected 403 from the WAF)." >&2
    exit 1
fi
echo "PASS [PoC]: post_render Drupalgeddon payload blocked (403)."

###############################################################################
# Regression: homepage and a legitimate login POST must still work.
###############################################################################
HOME=$($C -o /dev/null -w '%{http_code}' http://localhost/drupal/)
if [ "$HOME" != "200" ]; then
    echo "FAIL [Regression]: /drupal/ returned HTTP $HOME (expected 200 -- service down or over-blocked)." >&2
    exit 1
fi
echo "PASS [Regression]: /drupal/ homepage reachable (200)."

LOGIN=$($C -o /dev/null -w '%{http_code}' \
  -X POST 'http://localhost/drupal/?q=user&destination=user' \
  --data 'name=admin&pass=wrongpassword&form_id=user_login&op=Log+in')
if [ "$LOGIN" = "403" ]; then
    echo "FAIL [Regression]: legitimate Drupal login POST was blocked (403) -- rules too broad." >&2
    exit 1
fi
echo "PASS [Regression]: legitimate login POST passed the WAF (HTTP $LOGIN)."

echo "All checks passed."
exit 0
