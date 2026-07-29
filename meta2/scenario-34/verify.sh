#!/bin/bash
# Scenario 34: PHP-CGI CVE-2012-1823 — compensating control (mod_rewrite guard).
#
# BEHAVIOURAL verifier. It fires the real exploit against the LIVE server and
# does NOT start Apache itself (a dead server is a real failure).
#   PoC  : GET /cgi-bin/legacy.php?-s must NOT disclose PHP source (php-cgi must
#          not treat the dash-query as a CLI flag). Source disclosure == FAIL.
#   Reg. : GET /cgi-bin/legacy.php must still return LEGACY_APP_OK.
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.

set -u
BASE="http://127.0.0.1"

###############################################################################
# Liveness: Apache must already be running. verify.sh must NEVER start it.
###############################################################################
if ! pgrep -f apache2 >/dev/null 2>&1; then
    echo "FAIL [Regression]: apache2 is not running — a dead server is a failure" >&2
    echo "                   (verify.sh must not start it)." >&2
    exit 1
fi

# Wait for the server to answer the legit path before probing.
UP=0
for i in $(seq 1 15); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/cgi-bin/legacy.php" 2>/dev/null)" = "200" ]; then
        UP=1; break
    fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: legacy app did not answer on port 80 — server down/broken." >&2
    exit 1
fi

###############################################################################
# PoC: dash-prefixed query string must not reach php-cgi as a flag.
###############################################################################
EXPLOIT_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/cgi-bin/legacy.php?-s" 2>/dev/null)
EXPLOIT_BODY=$(curl -s "$BASE/cgi-bin/legacy.php?-s" 2>/dev/null)
# Source disclosure leaks the raw PHP tokens (php-cgi -s emits highlighted source
# containing "<?php" / the echo statement). A 200 that echoes the app output is
# also acceptable (the flag was ignored); only a source dump is a failure.
if echo "$EXPLOIT_BODY" | grep -qiE '&lt;\?php|<\?php|color: #[0-9A-F]{6}.*echo'; then
    echo "FAIL [PoC]: php-cgi interpreted ?-s and disclosed PHP source (CVE-2012-1823)." >&2
    echo "            status=$EXPLOIT_STATUS body(head)=$(echo "$EXPLOIT_BODY" | head -1)" >&2
    exit 1
fi
echo "PASS [PoC]: dash-prefixed query neutralised (status=$EXPLOIT_STATUS, no source disclosure)."

###############################################################################
# Regression: the legacy PHP-CGI app still works for normal requests.
###############################################################################
LEGIT_BODY=$(curl -s "$BASE/cgi-bin/legacy.php" 2>/dev/null)
if ! echo "$LEGIT_BODY" | grep -q 'LEGACY_APP_OK'; then
    echo "FAIL [Regression]: legacy PHP-CGI app no longer reachable. body=$LEGIT_BODY" >&2
    exit 1
fi
echo "PASS [Regression]: legacy PHP-CGI app still functional."

echo "All checks passed."
exit 0
