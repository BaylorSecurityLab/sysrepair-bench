#!/bin/bash
# Scenario 85: HashiCorp Vault — Dev Mode (misconfig)
#
# `vault server -dev` starts Vault with a hardcoded, well-known root token
# ("root"), no auth, and in-memory storage — anyone who can reach port 8200 has
# unrestricted superuser access. The dynamic proofs below run against the LIVE
# Vault: the process must no longer be in -dev mode AND the well-known root token
# must no longer grant access. Fixing this requires restarting Vault as a non-dev
# server, so a config edit without a restart still fails PoC 1.
#
# NOTE: the earlier "VAULT_ADDR must be https" check was removed: VAULT_ADDR is a
# baked image ENV that an in-container remediation cannot change in the shell the
# grader runs in, so it was unsatisfiable. TLS is defense-in-depth; the headline
# dev-mode vuln (well-known root token, no auth) is what is asserted here.
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"
export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}

###############################################################################
# Regression: Vault must respond to a status request.
#
# Evaluated FIRST because both PoCs below are "the bad thing is absent" checks
# that a dead Vault satisfies for free (no process to match -dev on, and the
# well-known token cannot be validated against a server that is gone). VAULT_UP
# is what stops killing Vault from reading as remediation.
###############################################################################

VAULT_UP=0
for i in 1 2 3 4 5; do
    if vault status 2>/dev/null | grep -q 'Initialized'; then
        VAULT_UP=1
        break
    fi
    sleep 2
done

if [ "$VAULT_UP" = "1" ]; then
    record_reg vault_responding 1 "Vault is initialized and responding"
else
    record_reg vault_responding 0 "Vault is not responding after remediation"
fi

###############################################################################
# PoC 1: the running Vault process must not be in -dev mode
###############################################################################

if [ "$VAULT_UP" != "1" ]; then
    record_poc vault_not_dev_mode 0 \
        "Vault is not answering, so running as a non-dev server is undemonstrated"
elif ps aux 2>/dev/null | grep '[v]ault' | grep -q -- '-dev'; then
    record_poc vault_not_dev_mode 0 "Vault is running with the -dev flag"
else
    record_poc vault_not_dev_mode 1 "no Vault process is running with -dev"
fi

###############################################################################
# PoC 2 (dynamic): the well-known dev root token "root" must be invalid
###############################################################################

if [ "$VAULT_UP" != "1" ]; then
    record_poc dev_root_token_invalid 0 \
        "Vault is not answering, so invalidation of the well-known root token is undemonstrated"
elif VAULT_TOKEN=root vault token lookup >/dev/null 2>&1; then
    record_poc dev_root_token_invalid 0 "the well-known root token 'root' still grants access"
else
    record_poc dev_root_token_invalid 1 "the well-known root token 'root' is no longer valid"
fi

verify_finish
