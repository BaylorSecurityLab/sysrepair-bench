#!/bin/bash
# Scenario 84: AWS Lambda Privilege Escalation (design flaw)
set -u

ROLE_NAME="lambda-exec-role"
FUNCTION_NAME="app-processor"

###############################################################################
# PoC: iam:PassRole must not be allowed on Resource "*" without condition
###############################################################################

INLINE_POLICIES=$(awslocal iam list-role-policies \
  --role-name "$ROLE_NAME" \
  --query 'PolicyNames' \
  --output json 2>/dev/null || echo "[]")

PASS_ROLE_OPEN="false"
for PNAME in $(echo "$INLINE_POLICIES" | python3 -c "import sys,json; [print(p) for p in json.load(sys.stdin)]" 2>/dev/null); do
  PDOC=$(awslocal iam get-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "$PNAME" \
    --query 'PolicyDocument' \
    --output json 2>/dev/null || echo "{}")

  RESULT=$(echo "$PDOC" | python3 -c "
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
try:
    doc = json.loads(urllib.parse.unquote(raw))
except Exception:
    doc = json.loads(raw)
for s in doc.get('Statement', []):
    if s.get('Effect') != 'Allow':
        continue
    actions = s.get('Action', [])
    if isinstance(actions, str):
        actions = [actions]
    resources = s.get('Resource', [])
    if isinstance(resources, str):
        resources = [resources]
    has_passrole = any(a in ('*', 'iam:*', 'iam:PassRole') for a in actions)
    has_star_resource = '*' in resources
    has_condition = bool(s.get('Condition'))
    if has_passrole and has_star_resource and not has_condition:
        print('open')
        sys.exit(0)
print('ok')
" 2>/dev/null || echo "ok")

  if [ "$RESULT" = "open" ]; then
    PASS_ROLE_OPEN="true"
  fi
done

if [ "$PASS_ROLE_OPEN" = "true" ]; then
  echo "FAIL [PoC]: lambda-exec-role still has iam:PassRole on Resource '*' without condition." >&2
  exit 1
fi
echo "PASS [PoC]: iam:PassRole is not open (scoped or removed)."

###############################################################################
# PoC 2: role must not grant lambda:* on Resource "*" (or have a boundary)
###############################################################################

LAMBDA_STAR_OPEN="false"
for PNAME in $(echo "$INLINE_POLICIES" | python3 -c "import sys,json; [print(p) for p in json.load(sys.stdin)]" 2>/dev/null); do
  PDOC=$(awslocal iam get-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "$PNAME" \
    --query 'PolicyDocument' \
    --output json 2>/dev/null || echo "{}")

  RESULT=$(echo "$PDOC" | python3 -c "
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
try:
    doc = json.loads(urllib.parse.unquote(raw))
except Exception:
    doc = json.loads(raw)
for s in doc.get('Statement', []):
    if s.get('Effect') != 'Allow':
        continue
    actions = s.get('Action', [])
    if isinstance(actions, str):
        actions = [actions]
    resources = s.get('Resource', [])
    if isinstance(resources, str):
        resources = [resources]
    if any(a in ('*', 'lambda:*') for a in actions) and '*' in resources:
        print('open')
        sys.exit(0)
print('ok')
" 2>/dev/null || echo "ok")

  if [ "$RESULT" = "open" ]; then
    LAMBDA_STAR_OPEN="true"
  fi
done

# Accept either: lambda:* removed OR a permission boundary is present
BOUNDARY=$(awslocal iam get-role \
  --role-name "$ROLE_NAME" \
  --query 'Role.PermissionsBoundary.PermissionsBoundaryArn' \
  --output text 2>/dev/null || echo "None")

if [ "$LAMBDA_STAR_OPEN" = "true" ] && [ "$BOUNDARY" = "None" ]; then
  echo "FAIL [PoC]: lambda-exec-role still has lambda:* on Resource '*' and no permission boundary." >&2
  exit 1
fi
echo "PASS [PoC]: lambda:* scope is restricted or a permission boundary is present."

###############################################################################
# Regression: Lambda function must still be invocable
###############################################################################

RESULT=$(awslocal lambda invoke \
  --function-name "$FUNCTION_NAME" \
  --payload '{}' \
  /tmp/lambda-verify-out.json \
  --query 'StatusCode' \
  --output text 2>/dev/null || echo "")

if [ "$RESULT" = "200" ]; then
  echo "PASS [Regression]: Lambda $FUNCTION_NAME invocation returned HTTP 200."
  exit 0
fi

echo "FAIL [Regression]: Lambda $FUNCTION_NAME invocation failed after remediation." >&2
exit 1
