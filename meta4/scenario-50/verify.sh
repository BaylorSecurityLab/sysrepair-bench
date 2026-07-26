#!/bin/bash
# Scenario 50: Kafka — no SASL authentication on the client listener (misconfig).
#
# BEHAVIOURAL check against the LIVE broker on 9092 using the in-image Kafka CLI:
#   * PoC:        an UNAUTHENTICATED admin request (list topics) must be REJECTED.
#                 At baseline (PLAINTEXT) it succeeds; once the client listener
#                 requires SASL_PLAINTEXT/PLAIN the broker refuses the handshake
#                 and the request fails.
#   * Regression: the broker must be alive AND a client with valid SASL
#                 credentials must succeed (create+list+delete a temp topic).
#
# Exit 0 = remediated (unauth rejected, authed works), Exit 1 = still open, broken,
# or config edited but broker not restarted.
set -u

BS="127.0.0.1:9092"
TOPICS="/opt/kafka/bin/kafka-topics.sh"
NONCE="srverify-$$-$RANDOM"

# Credentials the canonical remediation provisions (see solutions/.../scenario-50.sh
# and threat.md). The admin account must remain usable after the fix.
ADMIN_USER="admin"
ADMIN_PASS="admin-secret"

cleanup() { rm -f /tmp/unauth.props /tmp/authed.props 2>/dev/null; }
trap cleanup EXIT INT TERM

# Short client timeouts so an unauthenticated probe against a SASL-required
# broker fails fast instead of hanging (default.api.timeout.ms >= request.timeout.ms).
cat > /tmp/unauth.props <<'EOF'
request.timeout.ms=8000
default.api.timeout.ms=10000
retries=1
EOF

cat > /tmp/authed.props <<EOF
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="$ADMIN_USER" password="$ADMIN_PASS";
request.timeout.ms=10000
default.api.timeout.ms=20000
EOF

###############################################################################
# Regression 1: the broker must be listening on 9092 (a dead broker is a FAIL).
###############################################################################
LISTENING=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if nc -z 127.0.0.1 9092 2>/dev/null; then LISTENING=1; break; fi
    sleep 2
done
if [ "$LISTENING" -ne 1 ]; then
    echo "FAIL [Regression]: Kafka broker not listening on 9092 — dead service." >&2
    exit 1
fi
echo "PASS [Regression]: Kafka broker is listening on 9092."

###############################################################################
# PoC: an unauthenticated admin request must be REJECTED. rc==0 (success) means
# the broker served the request with no credentials -> still vulnerable.
###############################################################################
timeout 40 "$TOPICS" --bootstrap-server "$BS" --command-config /tmp/unauth.props --list >/dev/null 2>&1
RC=$?
if [ "$RC" -eq 0 ]; then
    echo "FAIL [PoC]: unauthenticated client listed topics (rc=0) — no SASL auth enforced." >&2
    exit 1
fi
echo "PASS [PoC]: unauthenticated client rejected (rc=$RC)."

###############################################################################
# Regression 2: a client with valid SASL credentials must be able to administer
# the broker. This defeats a cheat that blocks 9092 entirely instead of enforcing
# auth, and proves the broker is genuinely healthy.
###############################################################################
if ! timeout 40 "$TOPICS" --bootstrap-server "$BS" --command-config /tmp/authed.props \
        --create --topic "$NONCE" --partitions 1 --replication-factor 1 >/dev/null 2>&1; then
    echo "FAIL [Regression]: authenticated client could not create a topic — broker broken for valid creds." >&2
    exit 1
fi
if ! timeout 40 "$TOPICS" --bootstrap-server "$BS" --command-config /tmp/authed.props \
        --list 2>/dev/null | grep -q "$NONCE"; then
    echo "FAIL [Regression]: authenticated client could not see its own topic." >&2
    timeout 40 "$TOPICS" --bootstrap-server "$BS" --command-config /tmp/authed.props \
        --delete --topic "$NONCE" >/dev/null 2>&1
    exit 1
fi
# Clean up the temp topic (best effort; bounded by timeout).
timeout 40 "$TOPICS" --bootstrap-server "$BS" --command-config /tmp/authed.props \
    --delete --topic "$NONCE" >/dev/null 2>&1
echo "PASS [Regression]: authenticated client can administer the broker (create/list/delete)."

echo "All checks passed."
exit 0
