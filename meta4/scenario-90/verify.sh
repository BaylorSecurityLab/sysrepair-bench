#!/bin/bash
# Scenario 90: Git History Credential Leak (misconfig)
set -u

REPO="/opt/app"
SECRET="leaked_secret_42"

###############################################################################
# PoC: git log -p --all must not contain the leaked secret
###############################################################################

if git -C "${REPO}" log -p --all 2>/dev/null | grep -qF "${SECRET}"; then
    echo "FAIL [PoC]: '${SECRET}' found in git history of ${REPO}." >&2
    exit 1
fi
echo "PASS [PoC]: '${SECRET}' not present in git log -p --all."

###############################################################################
# Regression: config.env must exist and be loadable
###############################################################################

if [ -f "${REPO}/config.env" ]; then
    echo "PASS [Regression]: ${REPO}/config.env exists after remediation."
    exit 0
fi

echo "FAIL [Regression]: ${REPO}/config.env is missing after remediation." >&2
exit 1
