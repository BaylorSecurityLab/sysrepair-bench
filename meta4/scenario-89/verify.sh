#!/bin/bash
# Scenario 89: Docker ARG Secret in Layers (misconfig)
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

SECRET="ghp_abc123def456"

###############################################################################
# PoC 1: /etc/app/config.ini must not contain the leaked token
###############################################################################

if grep -qF "${SECRET}" /etc/app/config.ini 2>/dev/null; then
    record_poc config_ini_clean 0 "'${SECRET}' found in /etc/app/config.ini"
else
    record_poc config_ini_clean 1
fi

###############################################################################
# PoC 2: /proc/1/environ must not contain the token
###############################################################################

if tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -qF "${SECRET}"; then
    record_poc pid1_environ_clean 0 "'${SECRET}' found in /proc/1/environ"
else
    record_poc pid1_environ_clean 1
fi

###############################################################################
# Regression: /etc/app/config.ini must exist and be non-empty
###############################################################################

if [ -s /etc/app/config.ini ]; then
    record_reg config_ini_present 1
else
    record_reg config_ini_present 0 "/etc/app/config.ini is missing or empty after remediation"
fi

verify_finish
