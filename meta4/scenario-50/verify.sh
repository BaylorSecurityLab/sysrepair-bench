#!/bin/bash
# Scenario 50: Kafka 3.5 — No SASL Authentication / No ACLs (misconfig)
set -u

KAFKA_CONF="/opt/bitnami/kafka/config/server.properties"

if [ ! -f "$KAFKA_CONF" ]; then
    # Try alternate Bitnami path
    KAFKA_CONF="/bitnami/kafka/config/server.properties"
fi

###############################################################################
# PoC 1: server.properties must have sasl.enabled.mechanisms
###############################################################################

if [ ! -f "$KAFKA_CONF" ]; then
    echo "FAIL [PoC]: server.properties not found (checked /opt/bitnami and /bitnami paths)." >&2
    exit 1
fi

if ! grep -q "sasl.enabled.mechanisms" "$KAFKA_CONF" 2>/dev/null; then
    echo "FAIL [PoC]: server.properties does not set sasl.enabled.mechanisms." >&2
    exit 1
fi
echo "PASS [PoC]: sasl.enabled.mechanisms is configured."

###############################################################################
# PoC 2: server.properties must have AclAuthorizer
###############################################################################

if ! grep -q "authorizer.class.name=kafka.security.authorizer.AclAuthorizer" "$KAFKA_CONF" 2>/dev/null; then
    echo "FAIL [PoC]: server.properties does not set AclAuthorizer." >&2
    exit 1
fi
echo "PASS [PoC]: AclAuthorizer is configured."

###############################################################################
# Regression: Kafka broker must be listening on port 9092
###############################################################################

for i in 1 2 3 4 5; do
    if nc -z 127.0.0.1 9092 2>/dev/null; then
        echo "PASS [Regression]: Kafka broker is listening on port 9092."
        exit 0
    fi
    sleep 3
done

echo "FAIL [Regression]: Kafka broker port 9092 not reachable after remediation." >&2
exit 1
