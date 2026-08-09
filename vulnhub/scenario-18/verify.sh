#!/bin/bash
# Scenario 18: /var/www must not be world-writable.
#
# PoC checks:        no world-writable path under /var/www, and an unprivileged
#                    user can neither create a file in the webroot nor modify an
#                    existing served file
#
# Dynamic test: as the unprivileged 'nobody' user, actually try to (a) create a
# new file in the webroot and (b) modify an existing served file. Either
# succeeding is the real attack path (unauthenticated webshell drop). Also fail
# on any world-writable path found under /var/www.
#
# There is no service in this scenario (no .preserve-cmd) and no regression
# check: the finding is purely file-permission state, so regression_pass is
# reported as null rather than as a vacuous true. See lib/verifylib.sh.
#
# Two-component protocol: nothing aborts early.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

PROBE="/var/www/html/__s18_probe_$$.html"
cleanup(){ rm -f "$PROBE" 2>/dev/null; }
trap cleanup EXIT INT TERM

WW=$(find /var/www \( -type f -o -type d \) -perm -o+w 2>/dev/null | head -5)
if [ -n "$WW" ]; then
    record_poc no_world_writable_under_var_www 0 "world-writable paths under /var/www: $(printf '%s' "$WW" | tr '\n' ' ')"
else
    record_poc no_world_writable_under_var_www 1
fi

if id nobody >/dev/null 2>&1; then
    timeout 5 su -s /bin/sh nobody -c "echo s18-pwned > '$PROBE'" 2>/dev/null || true
    if [ -f "$PROBE" ]; then
        record_poc webroot_write_denied 0 "unprivileged user wrote a file into the webroot"
    else
        record_poc webroot_write_denied 1
    fi
    if [ -f /var/www/html/index.html ] && timeout 5 su -s /bin/sh nobody -c '[ -w /var/www/html/index.html ]' 2>/dev/null; then
        record_poc served_files_not_writable 0 "served file index.html is writable by unprivileged user"
    else
        record_poc served_files_not_writable 1
    fi
else
    echo "WARN: nobody user unavailable; relied on permission scan only"
fi

cleanup; trap - EXIT INT TERM
verify_finish
