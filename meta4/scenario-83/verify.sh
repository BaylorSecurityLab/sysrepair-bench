#!/bin/bash
# Scenario 83: AWS SNS Open Topic (misconfig)
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

# Wait for the LIVE LocalStack endpoint + SNS provisioning before probing.
#
# DEADLINE-bounded with a cap on each probe. The loop was written as 60 x
# `sleep 2` = an intended ~120s wait, but that counts only the sleeps: against a
# DEAD endpoint each awslocal call blocks ~13.6s on botocore connect retries, so
# it actually ran ~15 minutes and the verifier was killed by the runner (600s)
# and by production scorer.py (360s) before verify_finish — and a run with no
# summary is silently DROPPED from the collateral-damage denominator. The
# intended window is unchanged; it is now actually honoured.
_DEADLINE=$(( $(date +%s) + 120 ))
while [ "$(date +%s)" -lt "$_DEADLINE" ]; do
  timeout 5 awslocal sns list-topics \
    --query 'Topics[?ends_with(TopicArn,`:app-debug-events`)].TopicArn' \
    --output text 2>/dev/null | grep -q app-debug-events && break
  sleep 2
done

TOPIC_ARN=$(timeout 20 awslocal sns list-topics \
  --query 'Topics[?ends_with(TopicArn,`:app-debug-events`)].TopicArn' \
  --output text 2>/dev/null || echo "")

# The topic existing is a REGRESSION assertion: it is present on the untouched
# box, and the fix restricts its policy rather than deleting it.
if [ -n "${TOPIC_ARN:-}" ]; then
  record_reg sns_topic_present 1 "topic app-debug-events exists"
else
  record_reg sns_topic_present 0 "topic app-debug-events not found (deleted, or SNS unreachable)"
fi

###############################################################################
# PoC: topic policy must not contain Principal "*" for SNS:Subscribe
###############################################################################

POLICY=""
if [ -n "${TOPIC_ARN:-}" ]; then
  POLICY=$(awslocal sns get-topic-attributes \
    --topic-arn "$TOPIC_ARN" \
    --query 'Attributes.Policy' \
    --output text 2>/dev/null || echo "")
fi

OPEN_SUBSCRIBE=$(echo "${POLICY:-}" | python3 -c "
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
try:
    doc = json.loads(urllib.parse.unquote(raw))
except Exception:
    doc = json.loads(raw)
for s in doc.get('Statement', []):
    if s.get('Effect') != 'Allow':
        continue
    principal = s.get('Principal', '')
    is_star = (principal == '*') or (isinstance(principal, dict) and '*' in str(principal))
    if not is_star:
        continue
    actions = s.get('Action', [])
    if isinstance(actions, str):
        actions = [actions]
    if any(a in ('*', 'SNS:*', 'SNS:Subscribe') for a in actions):
        print('open')
        sys.exit(0)
print('restricted')
" 2>/dev/null || echo "error")

# COUPLED TO REACHABILITY: with the topic gone or SNS down there is no policy
# to inspect, so "not open" would be an artefact of a dead endpoint rather than
# evidence of remediation.
if [ -z "${TOPIC_ARN:-}" ] || [ -z "${POLICY:-}" ]; then
  record_poc no_open_subscribe 0 \
    "could not retrieve the topic policy, so removal of the open SNS:Subscribe grant is undemonstrated"
elif [ "$OPEN_SUBSCRIBE" = "open" ]; then
  record_poc no_open_subscribe 0 "topic policy still allows SNS:Subscribe for Principal '*'"
else
  record_poc no_open_subscribe 1 "topic policy does not allow open SNS:Subscribe"
fi

###############################################################################
# Regression: owner must still be able to publish
###############################################################################

MSG_ID=""
if [ -n "${TOPIC_ARN:-}" ]; then
  MSG_ID=$(awslocal sns publish \
    --topic-arn "$TOPIC_ARN" \
    --message "regression-test" \
    --query 'MessageId' \
    --output text 2>/dev/null || echo "")
fi

if [ -n "${MSG_ID:-}" ]; then
  record_reg authorized_publish_works 1 "authorized publish to app-debug-events succeeded (MessageId: $MSG_ID)"
else
  record_reg authorized_publish_works 0 "authorized publish to app-debug-events failed after remediation"
fi

verify_finish
