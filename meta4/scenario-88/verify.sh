#!/bin/bash
# Scenario 88: Plaintext Secret Baked Into Image — World-Readable (misconfig)
#
# The DB password is shipped in a world-readable file baked into the image. The
# dynamic/behavioral PoC exercises the real attack: an unprivileged user (or a
# co-tenant low-privilege process) reads the plaintext secret straight off the
# filesystem. After remediation the secret must not be recoverable by an
# unprivileged user, and a legitimate (restricted) config source must remain.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

SECRET="P@ssw0rd_2024"

###############################################################################
# PoC: an unprivileged user must NOT be able to read the plaintext secret
###############################################################################

if ! id nobody >/dev/null 2>&1; then
    record_poc secret_unreadable_by_nobody 0 "no 'nobody' user to test with"
elif su -s /bin/sh nobody -c "grep -rIqs '$SECRET' /opt /etc /run /home 2>/dev/null"; then
    record_poc secret_unreadable_by_nobody 0 \
        "plaintext secret is readable by unprivileged user 'nobody' from the image filesystem"
else
    record_poc secret_unreadable_by_nobody 1 \
        "plaintext secret is not readable by unprivileged user 'nobody'"
fi

###############################################################################
# PoC 2: the shipped app.env (if still present) must not be world/group readable
#        while containing the secret
###############################################################################

ENV_EXPOSED=0
if [ -f /opt/app/app.env ] && grep -qF "$SECRET" /opt/app/app.env 2>/dev/null; then
    PERM=$(stat -c '%a' /opt/app/app.env 2>/dev/null || true)
    case "${PERM:-}" in
        *[4567][0-9]|*[0-9][4567]) ENV_EXPOSED=1 ;;
    esac
fi
if [ "$ENV_EXPOSED" = "1" ]; then
    record_poc no_readable_secret_file 0 \
        "/opt/app/app.env (${PERM:-}) still holds the plaintext secret and is group/other-readable"
else
    record_poc no_readable_secret_file 1 "no world/group-readable file exposes the plaintext secret"
fi

###############################################################################
# Regression: a config source for the application must still exist
###############################################################################

if [ -f /run/secrets/db_password ] || [ -f /etc/app/config ] || [ -f /opt/app/app.env ]; then
    record_reg config_source_present 1 "an application config source still exists after remediation"
else
    record_reg config_source_present 0 \
        "no config source found (/run/secrets/db_password, /etc/app/config, or /opt/app/app.env)"
fi

verify_finish
