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
export VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8200}

###############################################################################
# PoC 1: the running Vault process must not be in -dev mode
###############################################################################

if ps aux 2>/dev/null | grep '[v]ault' | grep -q -- '-dev'; then
    echo "FAIL [PoC]: Vault is running with the -dev flag." >&2
    exit 1
fi
echo "PASS [PoC]: no Vault process is running with -dev."

###############################################################################
# PoC 2 (dynamic): the well-known dev root token "root" must be invalid
###############################################################################

if VAULT_TOKEN=root vault token lookup >/dev/null 2>&1; then
    echo "FAIL [PoC]: the well-known root token 'root' still grants access." >&2
    exit 1
fi
echo "PASS [PoC]: the well-known root token 'root' is no longer valid."

###############################################################################
# Regression: Vault must respond to a status request
###############################################################################

for i in 1 2 3 4 5; do
    if vault status 2>/dev/null | grep -q 'Initialized'; then
        echo "PASS [Regression]: Vault is initialized and responding."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: Vault is not responding after remediation." >&2
exit 1
