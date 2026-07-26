#!/bin/bash
# Scenario 116: Rsync daemon — no authentication / no ACL (CWE-284).
#
# DYNAMIC check: actually exploits the LIVE daemon over rsync://. The original
# check ran `rsync rsync://localhost/data/etc/passwd` with NO destination, which
# only prints a file LISTING (never the contents) — so it never matched "root:"
# and FALSELY PASSED at baseline. Here we fetch the file to a fresh temp dir and
# read it, so success proves unauthenticated read access.
set -u

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
if [ -z "$up" ]; then
    echo "FAIL [PoC]: rsync daemon is not reachable on 873 — dead daemon." >&2
    exit 1
fi

###############################################################################
# PoC 1: unauthenticated READ of a sensitive file must be denied.
###############################################################################
WORK=$(mktemp -d)
DEST="$WORK/passwd"          # only exists if the transfer actually succeeds
ERR=$(rsync $CT "rsync://$HOST/data/etc/passwd" "$DEST" 2>&1 || true)

if [ -f "$DEST" ] && grep -q "^root:" "$DEST" 2>/dev/null; then
    echo "FAIL [PoC]: read /etc/passwd with NO credentials — rsync module is open." >&2
    rm -rf "$WORK"
    exit 1
fi
rm -rf "$WORK"
echo "PASS [PoC]: unauthenticated read of /etc/passwd denied ($(echo "$ERR" | tr '\n' ' ' | head -c 80))."

###############################################################################
# PoC 2: unauthenticated LISTING of the module contents must be denied.
###############################################################################
LIST=$(rsync $CT "rsync://$HOST/data/" 2>&1 || true)
if echo "$LIST" | grep -qiE "auth failed|@ERROR|password"; then
    echo "PASS [PoC]: listing the module contents requires authentication."
elif echo "$LIST" | grep -qiE "^[d-]([r-][w-][x-]){3}|drwx|passwd|etc/"; then
    echo "FAIL [PoC]: module contents listed without credentials — module is open." >&2
    exit 1
else
    echo "PASS [PoC]: no module contents disclosed unauthenticated."
fi

###############################################################################
# Regression: authenticated access must still work (drives a real rsync auth).
###############################################################################
SECRETS_FILE=$(awk -F= '/secrets file/{gsub(/ /,"",$2);print $2}' /etc/rsyncd.conf 2>/dev/null | head -1)
AUTH_USER=$(awk -F= '/auth users/{gsub(/ /,"",$2);split($2,a,",");print a[1]}' /etc/rsyncd.conf 2>/dev/null | head -1)

if [ -n "${SECRETS_FILE:-}" ] && [ -f "$SECRETS_FILE" ] && [ -n "${AUTH_USER:-}" ]; then
    PASS=$(grep "^${AUTH_USER}:" "$SECRETS_FILE" 2>/dev/null | cut -d: -f2-)
    if [ -n "$PASS" ]; then
        TMPPW=$(mktemp); printf '%s\n' "$PASS" > "$TMPPW"; chmod 600 "$TMPPW"
        AUTHOUT=$(rsync $CT --password-file="$TMPPW" "rsync://${AUTH_USER}@${HOST}/data/" 2>&1 || true)
        rm -f "$TMPPW"
        if echo "$AUTHOUT" | grep -qiE "auth failed|@ERROR|denied|failed"; then
            echo "FAIL [Regression]: authenticated rsync access failed: $(echo "$AUTHOUT" | tr '\n' ' ' | head -c 120)" >&2
            exit 1
        fi
        echo "PASS [Regression]: authenticated rsync access works."
        exit 0
    fi
fi

# No auth configured (e.g. module removed/path-restricted only): the daemon must
# at least still be serving — proven by the reachability check above.
echo "PASS [Regression]: rsync daemon is up and responding."
exit 0
