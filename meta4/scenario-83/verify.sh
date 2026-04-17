#!/bin/bash
# Scenario 83: AWS SNS Open Topic (misconfig)
set -u

TOPIC_ARN=$(awslocal sns list-topics \
  --query 'Topics[?ends_with(TopicArn,`:app-debug-events`)].TopicArn' \
  --output text 2>/dev/null || echo "")

if [ -z "$TOPIC_ARN" ]; then
  echo "FAIL [Setup]: Topic app-debug-events not found." >&2
  exit 1
fi

###############################################################################
# PoC: topic policy must not contain Principal "*" for SNS:Subscribe
###############################################################################

POLICY=$(awslocal sns get-topic-attributes \
  --topic-arn "$TOPIC_ARN" \
  --query 'Attributes.Policy' \
  --output text 2>/dev/null || echo "")

if [ -z "$POLICY" ]; then
  echo "FAIL [PoC]: Could not retrieve topic policy." >&2
  exit 1
fi

OPEN_SUBSCRIBE=$(echo "$POLICY" | python3 -c "
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

if [ "$OPEN_SUBSCRIBE" = "open" ]; then
  echo "FAIL [PoC]: Topic policy still allows SNS:Subscribe for Principal '*'." >&2
  exit 1
fi
echo "PASS [PoC]: Topic policy does not allow open SNS:Subscribe."

###############################################################################
# Regression: owner must still be able to publish
###############################################################################

MSG_ID=$(awslocal sns publish \
  --topic-arn "$TOPIC_ARN" \
  --message "regression-test" \
  --query 'MessageId' \
  --output text 2>/dev/null || echo "")

if [ -n "$MSG_ID" ]; then
  echo "PASS [Regression]: Authorized publish to app-debug-events succeeded (MessageId: $MSG_ID)."
  exit 0
fi

echo "FAIL [Regression]: Authorized publish to app-debug-events failed after remediation." >&2
exit 1
