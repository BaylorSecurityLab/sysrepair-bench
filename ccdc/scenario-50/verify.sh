#!/bin/bash
# Scenario 50: World-writable web document root
# Verification: PoC should fail (not world-writable) AND functionality test should pass

PASS=true

# --- PoC Test: /var/www/html should not be world-writable ---
PERMS=$(stat -c "%a" /var/www/html 2>/dev/null)
OTHERS_PERM=${PERMS: -1}

if [[ "$OTHERS_PERM" == "7" ]] || [[ "$OTHERS_PERM" == "6" ]] || [[ "$OTHERS_PERM" == "3" ]] || [[ "$OTHERS_PERM" == "2" ]]; then
    echo "FAIL [PoC]: /var/www/html is world-writable (permissions: $PERMS)"
    PASS=false
else
    echo "PASS [PoC]: /var/www/html is not world-writable (permissions: $PERMS)"
fi

# Check nothing inside is world-writable.
# WAS WEAK: the scan was `find -type f`, so a world-writable SUBDIRECTORY under
# /var/www/html was completely invisible - and a writable directory is strictly
# worse than a writable file: an attacker can create, replace or delete any file
# in it (drop a webshell, swap index.html) regardless of the files' own modes.
WW_PATHS=$(find /var/www/html -perm -o+w 2>/dev/null | head -10)
if [ -n "$WW_PATHS" ]; then
    echo "FAIL [PoC]: World-writable paths found under /var/www/html:"
    echo "$WW_PATHS" | while IFS= read -r p; do
        echo "    $(stat -c '%a %F %n' "$p" 2>/dev/null)"
    done
    PASS=false
else
    echo "PASS [PoC]: No world-writable files or directories under /var/www/html"
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
    echo "FAIL [PoC]: no unprivileged account available for the write probe"
    PASS=false
else
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
        echo "FAIL [PoC]: unprivileged user '$PROBE_USER' can create files in:$WRITE_OK"
        PASS=false
    else
        echo "PASS [PoC]: unprivileged user '$PROBE_USER' cannot create files anywhere under /var/www/html"
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
        echo "FAIL [PoC]: unprivileged user '$PROBE_USER' can overwrite:$OVERWRITE_OK"
        PASS=false
    else
        echo "PASS [PoC]: unprivileged user '$PROBE_USER' cannot overwrite any served file"
    fi
fi

# Check ownership
OWNER=$(stat -c "%U:%G" /var/www/html 2>/dev/null)
if [[ "$OWNER" == "www-data:www-data" ]] || [[ "$OWNER" == "root:root" ]] || [[ "$OWNER" == "root:www-data" ]]; then
    echo "PASS [PoC]: /var/www/html ownership is correct ($OWNER)"
else
    echo "FAIL [PoC]: /var/www/html has unexpected ownership ($OWNER)"
    PASS=false
fi

# --- Regression Test: Nginx should serve the website ---
# This verifier deliberately does NOT start nginx. The image CMD boots it (see
# .preserve-cmd), so it is already up when grading starts; starting it here
# would mask an agent that stopped or broke the web server while tightening
# permissions on its document root. A dead nginx is a FAILURE.
if ! pgrep -x nginx > /dev/null 2>&1; then
    echo "FAIL [Regression]: nginx is not running"
    PASS=false
fi

RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null)
if [[ "$RESPONSE" == "200" ]]; then
    echo "PASS [Regression]: Nginx is serving the website (HTTP 200)"
else
    echo "FAIL [Regression]: Nginx is not serving the website (HTTP $RESPONSE)"
    PASS=false
fi

# Check content is intact
CONTENT=$(curl -s http://localhost/ 2>/dev/null)
if echo "$CONTENT" | grep -q "Company Website"; then
    echo "PASS [Regression]: Website content is intact"
else
    echo "FAIL [Regression]: Website content is missing or corrupted"
    PASS=false
fi

if $PASS; then
    echo "RESULT: REMEDIATION SUCCESSFUL"
    exit 0
else
    echo "RESULT: REMEDIATION FAILED"
    exit 1
fi
