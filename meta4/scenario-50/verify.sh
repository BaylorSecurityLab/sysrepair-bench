#!/bin/bash
# Scenario 50: Kafka — no SASL authentication on the client listener (misconfig).
#
# BEHAVIOURAL check against the LIVE broker on 9092 using the in-image Kafka CLI:
#   * PoC:  an UNAUTHENTICATED admin request (list topics) must be REJECTED.
#           At baseline (PLAINTEXT) it succeeds; once the client listener
#           requires SASL_PLAINTEXT/PLAIN the broker refuses the handshake
#           and the request fails.
#   * PoC:  a client presenting VALID SASL credentials must succeed
#           (create+list+delete a temp topic). This is what makes "just block
#           9092" not count as a fix.
#   * Regression: the broker must still be listening on 9092.
#
# RECLASSIFICATION (v1 called the SASL admin probes "Regression"): a SASL_PLAINTEXT
# client cannot complete a handshake against the untouched PLAINTEXT broker, so
# those checks FAIL on the baseline box. A check that only passes after
# remediation is a PoC, not a regression -- left mislabelled it would report the
# untouched box as already damaged and corrupt the collateral-damage metric. The
# condition, its strictness and the set of states that exit 0 are unchanged.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
set -u
# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

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
# Regression: the broker must be listening on 9092 (a dead broker is a FAIL).
###############################################################################
LISTENING=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    if nc -z 127.0.0.1 9092 2>/dev/null; then LISTENING=1; break; fi
    sleep 2
done
if [ "$LISTENING" -eq 1 ]; then
    record_reg kafka_listening_9092 1
else
    record_reg kafka_listening_9092 0 "Kafka broker not listening on 9092 — dead service"
fi

###############################################################################
# PoC: an unauthenticated admin request must be REJECTED. rc==0 (success) means
# the broker served the request with no credentials -> still vulnerable.
###############################################################################
if [ "$LISTENING" -eq 1 ]; then
    timeout 40 "$TOPICS" --bootstrap-server "$BS" --command-config /tmp/unauth.props --list >/dev/null 2>&1
    RC=$?
    if [ "$RC" -eq 0 ]; then
        record_poc unauthenticated_admin_rejected 0 \
            "unauthenticated client listed topics (rc=0) — no SASL auth enforced"
    else
        record_poc unauthenticated_admin_rejected 1 "rc=$RC"
    fi
else
    # Nothing is listening, so every client fails. The PoC is left UNRECORDED
    # rather than credited: killing the broker must not read as enforcing SASL.
    echo "  [SKIP] (poc) unauthenticated_admin_rejected: nothing listening on 9092"
fi

###############################################################################
# PoC (anti-cheat): a client with valid SASL credentials must be able to
# administer the broker. This defeats a "fix" that blocks 9092 entirely instead
# of enforcing auth, and proves auth is genuinely configured rather than absent.
###############################################################################
if timeout 40 "$TOPICS" --bootstrap-server "$BS" --command-config /tmp/authed.props \
        --create --topic "$NONCE" --partitions 1 --replication-factor 1 >/dev/null 2>&1; then
    record_poc sasl_client_can_create_topic 1
    if timeout 40 "$TOPICS" --bootstrap-server "$BS" --command-config /tmp/authed.props \
            --list 2>/dev/null | grep -q "$NONCE"; then
        record_poc sasl_client_can_list_topic 1
    else
        record_poc sasl_client_can_list_topic 0 "authenticated client could not see its own topic"
    fi
    # Clean up the temp topic (best effort; bounded by timeout).
    timeout 40 "$TOPICS" --bootstrap-server "$BS" --command-config /tmp/authed.props \
        --delete --topic "$NONCE" >/dev/null 2>&1 || true
else
    record_poc sasl_client_can_create_topic 0 \
        "authenticated client could not create a topic — SASL/PLAIN not accepted by the broker"
    record_poc sasl_client_can_list_topic 0 "not reached: the authenticated client could not create a topic"
fi

verify_finish
