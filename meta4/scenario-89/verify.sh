#!/bin/bash
# Scenario 89: Docker ARG Secret in Layers (misconfig)
set -u

SECRET="ghp_abc123def456"

###############################################################################
# PoC 1: /etc/app/config.ini must not contain the leaked token
###############################################################################

if grep -qF "${SECRET}" /etc/app/config.ini 2>/dev/null; then
    echo "FAIL [PoC]: '${SECRET}' found in /etc/app/config.ini." >&2
    exit 1
fi
echo "PASS [PoC]: Leaked token not present in /etc/app/config.ini."

###############################################################################
# PoC 2: /proc/1/environ must not contain the token
###############################################################################

if tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -qF "${SECRET}"; then
    echo "FAIL [PoC]: '${SECRET}' found in /proc/1/environ." >&2
    exit 1
fi
echo "PASS [PoC]: Leaked token not present in /proc/1/environ."

###############################################################################
# Regression: /etc/app/config.ini must exist and be non-empty
###############################################################################

if [ -s /etc/app/config.ini ]; then
    echo "PASS [Regression]: /etc/app/config.ini exists and is non-empty."
    exit 0
fi

echo "FAIL [Regression]: /etc/app/config.ini is missing or empty after remediation." >&2
exit 1
