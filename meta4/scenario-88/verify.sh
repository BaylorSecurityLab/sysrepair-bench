#!/bin/bash
# Scenario 88: Docker ENV-Embedded Password (misconfig)
set -u

SECRET="P@ssw0rd_2024"

###############################################################################
# PoC 1: env must not contain the hardcoded password
###############################################################################

if env | grep -qF "${SECRET}"; then
    echo "FAIL [PoC]: '${SECRET}' found in env output." >&2
    exit 1
fi
echo "PASS [PoC]: Password not present in environment variables."

###############################################################################
# PoC 2: /proc/1/environ must not contain the hardcoded password
###############################################################################

if tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -qF "${SECRET}"; then
    echo "FAIL [PoC]: '${SECRET}' found in /proc/1/environ." >&2
    exit 1
fi
echo "PASS [PoC]: Password not present in /proc/1/environ."

###############################################################################
# Regression: application config must be loadable from an alternative source
###############################################################################

# Accept a mounted secrets file OR a config file as proof of remediation
if [ -f /run/secrets/db_password ] || [ -f /etc/app/config ] || [ -f /opt/app/config ]; then
    echo "PASS [Regression]: Application config source exists after remediation."
    exit 0
fi

echo "FAIL [Regression]: No alternative config source found (/run/secrets/db_password, /etc/app/config, or /opt/app/config)." >&2
exit 1
