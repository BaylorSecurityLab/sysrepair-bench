#!/bin/bash
# Scenario 50: World-writable web document root
#
# PoC checks:        /var/www/html and everything under it is not world-writable
#                    and an unprivileged user really cannot create or overwrite
#                    content there
# Regression checks: nginx is still up and still serving the intact site
#
# Exit 0 = every check passed          (remediated, service intact)
# Exit 1 = at least one check failed
# Exit 42 = precondition does not hold on this host
#
# Two-component protocol: each check is recorded with its kind and NOTHING
# aborts early, so "chmod 700 the docroot so nginx can no longer read it" is
# reported as security_pass=true / regression_pass=false rather than collapsing
# into a bare exit 1. See lib/verifylib.sh.

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# --- PoC Test: /var/www/html should not be world-writable ---
PERMS=$(stat -c "%a" /var/www/html 2>/dev/null)
OTHERS_PERM=${PERMS: -1}

if [[ "$OTHERS_PERM" == "7" ]] || [[ "$OTHERS_PERM" == "6" ]] || [[ "$OTHERS_PERM" == "3" ]] || [[ "$OTHERS_PERM" == "2" ]]; then
    record_poc docroot_not_world_writable 0 "/var/www/html is world-writable (permissions: ${PERMS:-unknown})"
else
    record_poc docroot_not_world_writable 1
fi

# Check nothing inside is world-writable.
# WAS WEAK: the scan was `find -type f`, so a world-writable SUBDIRECTORY under
# /var/www/html was completely invisible - and a writable directory is strictly
# worse than a writable file: an attacker can create, replace or delete any file
# in it (drop a webshell, swap index.html) regardless of the files' own modes.
WW_PATHS=$(find /var/www/html -perm -o+w 2>/dev/null | head -10)
if [ -n "$WW_PATHS" ]; then
    record_poc no_world_writable_paths_in_docroot 0 "world-writable paths found under /var/www/html"
    echo "$WW_PATHS" | while IFS= read -r p; do
        echo "    $(stat -c '%a %F %n' "$p" 2>/dev/null)"
    done
else
    record_poc no_world_writable_paths_in_docroot 1
fi

# --- PoC Behavioural Test: an unprivileged user really cannot write there ---
# WAS WEAK: every check above is stat metadata. Drop to a real unprivileged
# account and actually try to create, modify and delete content in every
# directory of the tree - that is the exploit itself (webshell drop / defacement).
PROBE_USER=""
PROBE_GID=""
for u in nobody www-data daemon; do
    if id "$u" >/dev/null 2>&1; then
        PROBE_USER="$u"
        PROBE_GID=$(id -g "$u")
        break
    fi
done

if [ -z "$PROBE_USER" ]; then
    record_poc write_probe_account_available 0 "no unprivileged account available for the write probe"
else
    record_poc write_probe_account_available 1

    WRITE_OK=""
    while IFS= read -r d; do
        [ -d "$d" ] || continue
        PROBE="$d/.wwprobe.$$"
        if setpriv --reuid="$PROBE_USER" --regid="$PROBE_GID" --clear-groups \
                /bin/sh -c "printf x > '$PROBE'" 2>/dev/null; then
            WRITE_OK="$WRITE_OK $d"
            rm -f "$PROBE"
        fi
    done < <(find /var/www/html -type d 2>/dev/null)

    if [ -n "$WRITE_OK" ]; then
        record_poc unprivileged_cannot_create_files 0 "unprivileged user '$PROBE_USER' can create files in:$WRITE_OK"
    else
        record_poc unprivileged_cannot_create_files 1
    fi

    # And it must not be able to overwrite the served content either.
    OVERWRITE_OK=""
    while IFS= read -r f; do
        if setpriv --reuid="$PROBE_USER" --regid="$PROBE_GID" --clear-groups \
                /bin/sh -c "test -w '$f'" 2>/dev/null; then
            OVERWRITE_OK="$OVERWRITE_OK $f"
        fi
    done < <(find /var/www/html -type f 2>/dev/null)

    if [ -n "$OVERWRITE_OK" ]; then
        record_poc unprivileged_cannot_overwrite_files 0 "unprivileged user '$PROBE_USER' can overwrite:$OVERWRITE_OK"
    else
        record_poc unprivileged_cannot_overwrite_files 1
    fi
fi

# Check ownership
OWNER=$(stat -c "%U:%G" /var/www/html 2>/dev/null)
if [[ "$OWNER" == "www-data:www-data" ]] || [[ "$OWNER" == "root:root" ]] || [[ "$OWNER" == "root:www-data" ]]; then
    record_poc docroot_ownership_correct 1
else
    record_poc docroot_ownership_correct 0 "/var/www/html has unexpected ownership (${OWNER:-unknown})"
fi

# --- Regression Test: Nginx should serve the website ---
# This verifier deliberately does NOT start nginx. The image CMD boots it (see
# .preserve-cmd), so it is already up when grading starts; starting it here
# would mask an agent that stopped or broke the web server while tightening
# permissions on its document root. A dead nginx is a FAILURE.
if pgrep -x nginx > /dev/null 2>&1; then
    record_reg nginx_running 1
else
    record_reg nginx_running 0 "nginx is not running"
fi

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    record_reg nginx_serving_website 1
else
    record_reg nginx_serving_website 0 "nginx is not serving the website (HTTP ${RESPONSE:-none})"
fi

# Check content is intact
CONTENT=$(curl -s http://localhost/ 2>/dev/null)
if echo "$CONTENT" | grep -q "Company Website"; then
    record_reg website_content_intact 1
else
    record_reg website_content_intact 0 "website content is missing or corrupted"
fi

verify_finish
