#!/bin/bash
# Scenario 62: Dovecot 2.3.7 — Pre-Auth Buffer Overflow (CVE-2019-11500)
set -u

###############################################################################
# Pre-flight: verify NET_ADMIN capability (required for iptables checks)
###############################################################################

if ! iptables -L INPUT -n >/dev/null 2>&1; then
    echo "FAIL [Pre]: Container lacks NET_ADMIN capability (required for iptables checks)." >&2
    exit 1
fi

###############################################################################
# PoC 1: ssl_required must be set to yes in Dovecot config
###############################################################################

DOVECOT_CONF_DIR="/etc/dovecot"

if grep -rqE "ssl_required\s*=\s*yes" "$DOVECOT_CONF_DIR" 2>/dev/null; then
    echo "PASS [PoC 1]: ssl_required = yes is set in Dovecot config."
else
    echo "FAIL [PoC 1]: ssl_required = yes not found in Dovecot config." >&2
    exit 1
fi

###############################################################################
# PoC 2: login_trusted_networks must be set (not empty/missing)
###############################################################################

if grep -rqE "login_trusted_networks\s*=\s*\S+" "$DOVECOT_CONF_DIR" 2>/dev/null; then
    echo "PASS [PoC 2]: login_trusted_networks is configured in Dovecot config."
else
    echo "FAIL [PoC 2]: login_trusted_networks is missing or empty in Dovecot config." >&2
    exit 1
fi

###############################################################################
# PoC 3: iptables must block ports 143 and/or 993 from untrusted sources
###############################################################################

IPTABLES_OUT=$(iptables -L INPUT -n 2>/dev/null || true)

if echo "$IPTABLES_OUT" | grep -qE "(143|993)" && \
   echo "$IPTABLES_OUT" | grep -E "(143|993)" | grep -q "DROP"; then
    echo "PASS [PoC 3]: iptables DROP rules present for IMAP/IMAPS ports."
else
    echo "FAIL [PoC 3]: No iptables DROP rules found for ports 143 or 993." >&2
    exit 1
fi

###############################################################################
# Regression: Dovecot IMAP must still be reachable from localhost on port 143
###############################################################################

for i in 1 2 3 4 5; do
    if nc -z 127.0.0.1 143 2>/dev/null; then
        echo "PASS [Regression]: Dovecot IMAP is listening on port 143 from localhost."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: Dovecot IMAP port 143 not reachable from localhost." >&2
exit 1
