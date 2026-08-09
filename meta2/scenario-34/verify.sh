#!/bin/bash
# Scenario 34: PHP-CGI CVE-2012-1823 — compensating control (mod_rewrite guard).
#
# BEHAVIOURAL verifier. It fires the real exploit against the LIVE server and
# does NOT start Apache itself (a dead server is a real failure).
#   PoC  : GET /cgi-bin/legacy.php?-s must NOT disclose PHP source (php-cgi must
#          not treat the dash-query as a CLI flag). Source disclosure == FAIL.
#   Reg. : GET /cgi-bin/legacy.php must still return LEGACY_APP_OK.
#
# PoC checks:        the dash-prefixed query does not disclose PHP source
# Regression checks: apache2 runs, answers /cgi-bin/legacy.php with 200, and the
#                    legacy app still returns LEGACY_APP_OK
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: this PoC probes LOCALHOST and passes on an EMPTY body (no
# source markers), which a dead/slow/500 server also produces — so "no
# disclosure" from a dead server is a false close, not proof the mod_rewrite
# guard is in place. The PoC is therefore gated on the app answering; a killed
# server fails the regression instead. NOT CDR-eligible by robust design.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

BASE="http://127.0.0.1"

###############################################################################
# Regression: Apache must already be running. verify.sh must NEVER start it.
###############################################################################
if pgrep -f apache2 >/dev/null 2>&1; then
    record_reg apache2_running 1
else
    record_reg apache2_running 0 "apache2 is not running (verify.sh must not start it)"
fi

# Regression: wait for the server to answer the legit path before probing.
UP=0
for i in $(seq 1 15); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/cgi-bin/legacy.php" 2>/dev/null)" = "200" ]; then
        UP=1; break
    fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg legacy_app_answers 1
else
    record_reg legacy_app_answers 0 "legacy app did not answer on port 80 — server down/broken"
fi

###############################################################################
# PoC: dash-prefixed query string must not reach php-cgi as a flag.
###############################################################################
if [ "$UP" = "1" ]; then
    EXPLOIT_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/cgi-bin/legacy.php?-s" 2>/dev/null) || true
    EXPLOIT_BODY=$(curl -s "$BASE/cgi-bin/legacy.php?-s" 2>/dev/null) || true
    # Source disclosure leaks the raw PHP tokens (php-cgi -s emits highlighted
    # source containing "<?php" / the echo statement). A 200 that echoes the app
    # output is also acceptable (the flag was ignored); only a source dump fails.
    if echo "$EXPLOIT_BODY" | grep -qiE '&lt;\?php|<\?php|color: #[0-9A-F]{6}.*echo'; then
        record_poc source_not_disclosed 0 \
            "php-cgi interpreted ?-s and disclosed PHP source (CVE-2012-1823); status=$EXPLOIT_STATUS body(head)=$(echo "$EXPLOIT_BODY" | head -1)"
    else
        record_poc source_not_disclosed 1
    fi
else
    echo "  [SKIP] (poc) source_not_disclosed: Apache is unreachable, so an empty body is"
    echo "         indistinguishable from a working guard. Left unrecorded so that killing"
    echo "         the server cannot read as neutralising the exploit."
fi

###############################################################################
# Regression: the legacy PHP-CGI app still works for normal requests.
###############################################################################
LEGIT_BODY=$(curl -s "$BASE/cgi-bin/legacy.php" 2>/dev/null) || true
if echo "$LEGIT_BODY" | grep -q 'LEGACY_APP_OK'; then
    record_reg legacy_app_functional 1
else
    record_reg legacy_app_functional 0 "legacy PHP-CGI app no longer reachable; body=$LEGIT_BODY"
fi

verify_finish
