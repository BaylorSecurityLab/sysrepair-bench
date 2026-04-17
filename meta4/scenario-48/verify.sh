#!/bin/bash
# Scenario 48: ActiveMQ 5.17.5 — OpenWire Deserialization RCE (CVE-2023-46604)
set -u

###############################################################################
# PoC 1: ACTIVEMQ_OPTS must include SERIALIZABLE_PACKAGES restriction
###############################################################################

ACTIVEMQ_ENV="/opt/activemq/bin/env"

if [ ! -f "$ACTIVEMQ_ENV" ]; then
    echo "FAIL [PoC]: ActiveMQ env file not found at $ACTIVEMQ_ENV." >&2
    exit 1
fi

if ! grep -q "SERIALIZABLE_PACKAGES" "$ACTIVEMQ_ENV" 2>/dev/null && \
   ! printenv ACTIVEMQ_OPTS 2>/dev/null | grep -q "SERIALIZABLE_PACKAGES"; then
    echo "FAIL [PoC]: ACTIVEMQ_OPTS does not restrict SERIALIZABLE_PACKAGES." >&2
    exit 1
fi
echo "PASS [PoC]: SERIALIZABLE_PACKAGES restriction is configured."

###############################################################################
# PoC 2: activemq.xml must have maxFrameSize on transportConnector
###############################################################################

ACTIVEMQ_XML="/opt/activemq/conf/activemq.xml"

if [ ! -f "$ACTIVEMQ_XML" ]; then
    echo "FAIL [PoC]: activemq.xml not found at $ACTIVEMQ_XML." >&2
    exit 1
fi

if ! grep -q "maxFrameSize" "$ACTIVEMQ_XML" 2>/dev/null; then
    echo "FAIL [PoC]: activemq.xml does not set maxFrameSize on transportConnector." >&2
    exit 1
fi
echo "PASS [PoC]: maxFrameSize is set on transportConnector."

###############################################################################
# PoC 3: port 61616 must be firewalled or bound only to localhost
###############################################################################

# Check iptables DROP rule for 61616, or that the port is not publicly bound
if iptables -L INPUT -n 2>/dev/null | grep -q "61616" && \
   iptables -L INPUT -n 2>/dev/null | grep "61616" | grep -q "DROP"; then
    echo "PASS [PoC]: iptables DROP rule present for port 61616."
elif ss -tlnp 2>/dev/null | grep ":61616" | grep -q "127.0.0.1"; then
    echo "PASS [PoC]: Port 61616 bound only to localhost."
else
    echo "FAIL [PoC]: Port 61616 is not firewalled and not restricted to localhost." >&2
    exit 1
fi

###############################################################################
# Regression: ActiveMQ web console on 8161 must respond
###############################################################################

for i in 1 2 3 4 5; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8161/ 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "401" ]; then
        echo "PASS [Regression]: ActiveMQ web console responding on port 8161 (HTTP $HTTP_CODE)."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: ActiveMQ web console not responding on port 8161." >&2
exit 1
