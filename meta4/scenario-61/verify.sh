#!/bin/bash
# Scenario 61: Exim 4.96 — SMTP Smuggling (CVE-2023-51766)
set -u

###############################################################################
# PoC: chunking_advertise_hosts must be set to empty in Exim config
###############################################################################

EXIM_CONF_DIR="/etc/exim4"

# Search all exim config files for the chunking_advertise_hosts setting
if grep -rqE "chunking_advertise_hosts\s*=\s*$" "$EXIM_CONF_DIR" 2>/dev/null || \
   grep -rqE "chunking_advertise_hosts\s*=$" "$EXIM_CONF_DIR" 2>/dev/null; then
    echo "PASS [PoC]: chunking_advertise_hosts is set to empty in Exim config."
else
    echo "FAIL [PoC]: chunking_advertise_hosts is not set to empty in Exim config." >&2
    exit 1
fi

###############################################################################
# PoC 2: pipelining_advertise_hosts must be restricted (not wildcarded)
###############################################################################

if grep -rqE "pipelining_advertise_hosts\s*=\s*\*" "$EXIM_CONF_DIR" 2>/dev/null; then
    echo "FAIL [PoC]: pipelining_advertise_hosts is still set to '*' (all hosts)." >&2
    exit 1
fi
echo "PASS [PoC]: pipelining_advertise_hosts is not wildcarded to all hosts."

# PoC (behavioral): verify EHLO response does not advertise CHUNKING
# CHUNKING must be disabled to prevent SMTP smuggling
for i in 1 2 3 4 5; do
    EHLO_RESP=$(echo "EHLO test" | nc -q1 127.0.0.1 25 2>/dev/null || true)
    if echo "$EHLO_RESP" | grep -q "^250"; then
        if echo "$EHLO_RESP" | grep -qi 'CHUNKING'; then
            echo "FAIL [PoC]: Exim still advertises CHUNKING in EHLO response." >&2
            exit 1
        fi
        echo "PASS [PoC]: Exim EHLO response does not advertise CHUNKING."
        break
    fi
    sleep 2
done

###############################################################################
# Regression: Exim must accept EHLO on port 25
###############################################################################

for i in 1 2 3 4 5; do
    RESPONSE=$(echo "EHLO test" | nc -q1 127.0.0.1 25 2>/dev/null || true)
    if echo "$RESPONSE" | grep -q "^250"; then
        echo "PASS [Regression]: Exim responds to EHLO on port 25."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: Exim not responding to EHLO on port 25." >&2
exit 1
