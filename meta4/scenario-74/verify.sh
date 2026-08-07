#!/bin/bash
# Scenario 74: Plaintext secret shipped in a world-readable file (CWE-312).
#
# The DB password / API key ship in a world-readable file baked into the image.
# The behavioral PoC exercises the real attack: an unprivileged user (or a
# co-tenant low-privilege process) reads a plaintext credential straight off the
# filesystem.
#
# IMPORTANT: this check keys on the SECRET PATTERN (assignment markers like
# DB_PASSWORD= / API_KEY=) and on FILE READABILITY / MODE - NEVER on a literal
# secret value. Rotating the value while leaving the file world/group-readable
# (e.g. `sed -i 's/OldSecret/NewSecret/' /etc/appsecrets/db.conf`) is NOT
# remediation and MUST still FAIL. Restricting the file to root-only (0600) or
# removing it and serving the secret from a restricted source MUST PASS.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# Assignment-of-a-literal secret markers (value-independent). Covers BOTH seeded
# secrets (DB_PASSWORD and API_KEY) so rotating either VALUE cannot bypass the
# check. The trailing [A-Za-z0-9] requires an actual literal value after '=', so
# application code that loads the var from a restricted source
# (`DB_PASSWORD=$(cat /run/secrets/...)`) is NOT flagged - only cleartext values
# baked into a file are. (No quote chars in the regex: it is embedded in a
# double-quoted `su -c` string below.)
SECRET_RE='(DB_PASSWORD|API_KEY)=[A-Za-z0-9]'
# NB: deliberately excludes /tmp - the harness drops verify.sh/solve.sh there and
# this very script contains the marker strings above, which would self-match.
SCAN_DIRS='/etc /opt /run /home /usr/local /srv /var'

###############################################################################
# PoC: an unprivileged user must NOT be able to read ANY file that holds a
#      secret assignment - independent of the value it currently contains.
###############################################################################
if ! id nobody >/dev/null 2>&1; then
    record_poc secret_unreadable_by_nobody 0 "no 'nobody' user to run the unprivileged-read PoC with"
elif timeout 30 su -s /bin/sh nobody -c "grep -rIlsE '$SECRET_RE' $SCAN_DIRS 2>/dev/null | grep -q ."; then
    LEAK=$(timeout 30 su -s /bin/sh nobody -c "grep -rIlsE '$SECRET_RE' $SCAN_DIRS 2>/dev/null" | head -3 | tr '\n' ' ' || true)
    record_poc secret_unreadable_by_nobody 0 \
        "unprivileged user 'nobody' can read a file holding a plaintext secret: ${LEAK:-} (a rotated value in a still-readable file is NOT remediation - restrict or remove it)"
else
    record_poc secret_unreadable_by_nobody 1 \
        "no file holding a secret assignment is readable by unprivileged user 'nobody'"
fi

###############################################################################
# PoC 2: no world/group-readable file anywhere may hold a secret assignment
#        (checked as root so files 'nobody' cannot even traverse are still
#        caught - defence in depth, matches the threat model's second clause).
###############################################################################
HITS=$(grep -rIlsE "$SECRET_RE" $SCAN_DIRS 2>/dev/null || true)
EXPOSED=""
for f in $HITS; do
    [ -f "$f" ] || continue
    PERM=$(stat -c '%a' "$f" 2>/dev/null) || continue
    case "$PERM" in
        *[4567][0-9]|*[0-9][4567])
            EXPOSED="$EXPOSED $f(mode $PERM)"
            ;;
    esac
done
if [ -n "$EXPOSED" ]; then
    record_poc no_readable_secret_file 0 \
        "file(s) holding a secret assignment are group/other-readable:$EXPOSED"
else
    record_poc no_readable_secret_file 1 "no world/group-readable file holds a secret assignment"
fi

###############################################################################
# Regression: an application secret source must still exist (the fix must not
# simply delete everything and break the app's ability to load its credential).
###############################################################################
if [ -f /run/secrets/db_password ] || [ -f /etc/app/config ] || [ -f /etc/appsecrets/db.conf ]; then
    record_reg secret_source_present 1 "an application secret source still exists after remediation"
else
    record_reg secret_source_present 0 \
        "no secret source found (/run/secrets/db_password, /etc/app/config, or /etc/appsecrets/db.conf)"
fi

verify_finish
