#!/bin/bash
# Scenario 84: AWS Lambda Privilege Escalation (design flaw)
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

ROLE_NAME="lambda-exec-role"
FUNCTION_NAME="app-processor"

# Wait for the LIVE LocalStack endpoint + Lambda/IAM provisioning before probing.
# LS_UP records whether it ever answered: both PoCs below are "we found no open
# grant" checks, and with the IAM API gone they enumerate nothing and would be
# credited for it.
#
# DEADLINE-bounded with a cap on each probe. The loop was written as 90 x
# `sleep 2` = an intended ~180s wait, but that counts only the sleeps: against a
# DEAD endpoint each awslocal call blocks ~13.6s on botocore connect retries, so
# it actually ran far past the runner's 600s and production scorer.py's 360s
# verify budget — and a run with no summary is silently DROPPED from the
# collateral-damage denominator. The intended window is unchanged; it is now
# actually honoured.
LS_UP=0
_DEADLINE=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "$_DEADLINE" ]; do
  if timeout 5 awslocal lambda get-function --function-name "$FUNCTION_NAME" >/dev/null 2>&1; then
    LS_UP=1
    break
  fi
  sleep 2
done

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

if [ "$LS_UP" != "1" ]; then
  record_poc passrole_not_open 0 \
    "LocalStack never answered, so scoping of iam:PassRole is undemonstrated"
elif [ "$PASS_ROLE_OPEN" = "true" ]; then
  record_poc passrole_not_open 0 \
    "lambda-exec-role still has iam:PassRole on Resource '*' without condition"
else
  record_poc passrole_not_open 1 "iam:PassRole is not open (scoped or removed)"
fi

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

if [ "$LS_UP" != "1" ]; then
  record_poc lambda_star_restricted 0 \
    "LocalStack never answered, so restriction of lambda:* is undemonstrated"
elif [ "$LAMBDA_STAR_OPEN" = "true" ] && [ "$BOUNDARY" = "None" ]; then
  record_poc lambda_star_restricted 0 \
    "lambda-exec-role still has lambda:* on Resource '*' and no permission boundary"
else
  record_poc lambda_star_restricted 1 "lambda:* scope is restricted or a permission boundary is present"
fi

###############################################################################
# Regression: Lambda function must still exist and reference its exec role
#
# Actual invocation requires a Docker runtime that LocalStack cannot use from
# inside this container (the function reports State=Failed regardless of the
# policy), so executing it is infeasible in the harness. The remediation edits
# only the role's inline policy, so the meaningful regression is that the
# function still exists and still references lambda-exec-role — this catches a
# bad "fix" that deletes the function or detaches its role.
###############################################################################

ROLE_ARN=$(awslocal lambda get-function-configuration \
  --function-name "$FUNCTION_NAME" \
  --query 'Role' \
  --output text 2>/dev/null || echo "")

if echo "${ROLE_ARN:-}" | grep -q "role/$ROLE_NAME"; then
  record_reg lambda_still_bound_to_role 1 "Lambda $FUNCTION_NAME still exists and references $ROLE_NAME"
else
  record_reg lambda_still_bound_to_role 0 \
    "Lambda $FUNCTION_NAME missing or no longer references $ROLE_NAME after remediation"
fi

verify_finish
