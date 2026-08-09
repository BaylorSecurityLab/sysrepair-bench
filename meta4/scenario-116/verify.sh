#!/bin/bash
# Scenario 116: Rsync daemon — no authentication / no ACL (CWE-284).
#
# DYNAMIC check: actually exploits the LIVE daemon over rsync://. The original
# check ran `rsync rsync://localhost/data/etc/passwd` with NO destination, which
# only prints a file LISTING (never the contents) — so it never matched "root:"
# and FALSELY PASSED at baseline. Here we fetch the file to a fresh temp dir and
# read it, so success proves unauthenticated read access.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# Pin to IPv4: rsyncd listens on IPv4 only, but `localhost` resolves to ::1
# first, which makes rsync intermittently report "Connection refused (::1)"
# instead of falling through — a false PASS/FAIL hazard. Force IPv4 everywhere.
HOST="127.0.0.1"
CT="-4 --contimeout=5 --timeout=10"

###############################################################################
# Wait for the daemon to answer (module listing is allowed even when auth is on).
###############################################################################
up=""
for i in $(seq 1 30); do
    OUT=$(rsync $CT "rsync://$HOST/" 2>&1 || true)
    if ! echo "$OUT" | grep -qiE "connection refused|unable to connect|no route|timed out"; then
        up="yes"; break
    fi
    sleep 1
done
# RECLASSIFIED poc -> regression (UNREACHABILITY RULE). The original charged an
# unreachable daemon to the PoC ("dead daemon"), so an agent that simply killed
# rsyncd was scored on the security axis for it. A silent 873 is a destroyed
# service: record it as a REGRESSION failure and emit no PoC verdict for the same
# condition. Condition, strictness and the exit-0 state set are unchanged.
if [ -n "$up" ]; then
    record_reg rsync_daemon_reachable 1
else
    record_reg rsync_daemon_reachable 0 "rsync daemon is not reachable on 873 - dead daemon"
fi

###############################################################################
# PoC 1: unauthenticated READ of a sensitive file must be denied.
###############################################################################
WORK=$(mktemp -d)
DEST="$WORK/passwd"          # only exists if the transfer actually succeeds
ERR=$(rsync $CT "rsync://$HOST/data/etc/passwd" "$DEST" 2>&1 || true)

if [ -f "$DEST" ] && grep -q "^root:" "$DEST" 2>/dev/null; then
    record_poc unauth_read_denied 0 "read /etc/passwd with NO credentials - rsync module is open"
else
    record_poc unauth_read_denied 1 "unauthenticated read of /etc/passwd denied ($(echo "$ERR" | tr '\n' ' ' | head -c 80 || true))"
fi
rm -rf "$WORK"

###############################################################################
# PoC 2: unauthenticated LISTING of the module contents must be denied.
###############################################################################
LIST=$(rsync $CT "rsync://$HOST/data/" 2>&1 || true)
if echo "$LIST" | grep -qiE "auth failed|@ERROR|password"; then
    record_poc unauth_listing_denied 1 "listing the module contents requires authentication"
elif echo "$LIST" | grep -qiE "^[d-]([r-][w-][x-]){3}|drwx|passwd|etc/"; then
    record_poc unauth_listing_denied 0 "module contents listed without credentials - module is open"
else
    record_poc unauth_listing_denied 1 "no module contents disclosed unauthenticated"
fi

###############################################################################
# Regression: authenticated access must still work (drives a real rsync auth).
###############################################################################
SECRETS_FILE=$(awk -F= '/secrets file/{gsub(/ /,"",$2);print $2}' /etc/rsyncd.conf 2>/dev/null | head -1)
AUTH_USER=$(awk -F= '/auth users/{gsub(/ /,"",$2);split($2,a,",");print a[1]}' /etc/rsyncd.conf 2>/dev/null | head -1)

# NB: the password variable is deliberately NOT called PASS. verifylib defines
# PASS=0 and `verify_finish` runs `exit $PASS`, so reusing that name here would
# make a successful run exit with the rsync password instead of 0.
if [ -n "${SECRETS_FILE:-}" ] && [ -f "$SECRETS_FILE" ] && [ -n "${AUTH_USER:-}" ]; then
    RSYNC_PW=$(grep "^${AUTH_USER}:" "$SECRETS_FILE" 2>/dev/null | cut -d: -f2- || true)
    if [ -n "$RSYNC_PW" ]; then
        TMPPW=$(mktemp); printf '%s\n' "$RSYNC_PW" > "$TMPPW"; chmod 600 "$TMPPW"
        AUTHOUT=$(rsync $CT --password-file="$TMPPW" "rsync://${AUTH_USER}@${HOST}/data/" 2>&1 || true)
        rm -f "$TMPPW"
        if echo "$AUTHOUT" | grep -qiE "auth failed|@ERROR|denied|failed"; then
            record_reg authenticated_access_works 0 "authenticated rsync access failed: $(echo "$AUTHOUT" | tr '\n' ' ' | head -c 120 || true)"
        else
            record_reg authenticated_access_works 1 "authenticated rsync access works"
        fi
    fi
fi

# When no auth is configured (e.g. module removed/path-restricted only) the
# daemon must at least still be serving -- that is the rsync_daemon_reachable
# regression check recorded above, so nothing further is needed here.

verify_finish
