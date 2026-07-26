#!/bin/bash
# Scenario 88: Plaintext Secret Baked Into Image — World-Readable (misconfig)
#
# The DB password is shipped in a world-readable file baked into the image. The
# dynamic/behavioral PoC exercises the real attack: an unprivileged user (or a
# co-tenant low-privilege process) reads the plaintext secret straight off the
# filesystem. After remediation the secret must not be recoverable by an
# unprivileged user, and a legitimate (restricted) config source must remain.
set -u

SECRET="P@ssw0rd_2024"

###############################################################################
# PoC: an unprivileged user must NOT be able to read the plaintext secret
###############################################################################

if id nobody >/dev/null 2>&1; then
    if su -s /bin/sh nobody -c "grep -rIqs '$SECRET' /opt /etc /run /home 2>/dev/null"; then
        echo "FAIL [PoC]: plaintext secret is readable by unprivileged user 'nobody' from the image filesystem." >&2
        exit 1
    fi
    echo "PASS [PoC]: plaintext secret is not readable by unprivileged user 'nobody'."
else
    echo "SKIP [PoC]: no 'nobody' user to test with." >&2
    exit 1
fi

###############################################################################
# PoC 2: the shipped app.env (if still present) must not be world/group readable
#        while containing the secret
###############################################################################

if [ -f /opt/app/app.env ] && grep -qF "$SECRET" /opt/app/app.env 2>/dev/null; then
    PERM=$(stat -c '%a' /opt/app/app.env 2>/dev/null)
    case "$PERM" in
        *[4567][0-9]|*[0-9][4567])
            echo "FAIL [PoC]: /opt/app/app.env ($PERM) still holds the plaintext secret and is group/other-readable." >&2
            exit 1
            ;;
    esac
fi
echo "PASS [PoC]: no world/group-readable file exposes the plaintext secret."

###############################################################################
# Regression: a config source for the application must still exist
###############################################################################

if [ -f /run/secrets/db_password ] || [ -f /etc/app/config ] || [ -f /opt/app/app.env ]; then
    echo "PASS [Regression]: an application config source still exists after remediation."
    exit 0
fi

echo "FAIL [Regression]: no config source found (/run/secrets/db_password, /etc/app/config, or /opt/app/app.env)." >&2
exit 1
