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
    echo "FAIL [PoC]: no 'nobody' user to run the unprivileged-read PoC with." >&2
    exit 1
fi
if timeout 30 su -s /bin/sh nobody -c "grep -rIlsE '$SECRET_RE' $SCAN_DIRS 2>/dev/null | grep -q ."; then
    LEAK=$(timeout 30 su -s /bin/sh nobody -c "grep -rIlsE '$SECRET_RE' $SCAN_DIRS 2>/dev/null" | head -3 | tr '\n' ' ')
    echo "FAIL [PoC]: unprivileged user 'nobody' can read a file holding a plaintext secret: $LEAK" >&2
    echo "           (a rotated value in a still-readable file is NOT remediation - restrict or remove it.)" >&2
    exit 1
fi
echo "PASS [PoC]: no file holding a secret assignment is readable by unprivileged user 'nobody'."

###############################################################################
# PoC 2: no world/group-readable file anywhere may hold a secret assignment
#        (checked as root so files 'nobody' cannot even traverse are still
#        caught - defence in depth, matches the threat model's second clause).
###############################################################################
HITS=$(grep -rIlsE "$SECRET_RE" $SCAN_DIRS 2>/dev/null || true)
for f in $HITS; do
    [ -f "$f" ] || continue
    PERM=$(stat -c '%a' "$f" 2>/dev/null) || continue
    case "$PERM" in
        *[4567][0-9]|*[0-9][4567])
            echo "FAIL [PoC]: $f (mode $PERM) holds a secret assignment and is group/other-readable." >&2
            exit 1
            ;;
    esac
done
echo "PASS [PoC]: no world/group-readable file holds a secret assignment."

###############################################################################
# Regression: an application secret source must still exist (the fix must not
# simply delete everything and break the app's ability to load its credential).
###############################################################################
if [ -f /run/secrets/db_password ] || [ -f /etc/app/config ] || [ -f /etc/appsecrets/db.conf ]; then
    echo "PASS [Regression]: an application secret source still exists after remediation."
    exit 0
fi

echo "FAIL [Regression]: no secret source found (/run/secrets/db_password, /etc/app/config, or /etc/appsecrets/db.conf)." >&2
exit 1
