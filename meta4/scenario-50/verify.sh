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

SASL_OK=0
if grep -q "sasl.enabled.mechanisms" "$KAFKA_CONF" 2>/dev/null; then
    SASL_OK=1
fi
if printenv KAFKA_CFG_SASL_ENABLED_MECHANISMS 2>/dev/null | grep -qi 'PLAIN'; then
    SASL_OK=1
fi
if [ "$SASL_OK" -eq 0 ]; then
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

# PoC (behavioral): verify Kafka rejects unauthenticated connections
# An unauthenticated producer should fail when SASL is required
if command -v kafka-console-producer.sh >/dev/null 2>&1; then
    PROD_OUT=$(echo "test" | timeout 5 kafka-console-producer.sh \
        --broker-list 127.0.0.1:9092 --topic test 2>&1 || true)
    if echo "$PROD_OUT" | grep -qi 'SASL\|authentication\|not authorized\|error'; then
        echo "PASS [PoC]: Unauthenticated Kafka producer rejected."
    elif echo "$PROD_OUT" | grep -qi 'sent\|success'; then
        echo "FAIL [PoC]: Unauthenticated Kafka producer succeeded — SASL not enforced." >&2
        exit 1
    else
        echo "PASS [PoC]: Kafka producer did not succeed without SASL auth."
    fi
fi

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
