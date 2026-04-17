#!/bin/bash
# Scenario 80: AWS IAM Policy Version Rollback (design flaw)
set -u

POLICY_ARN="arn:aws:iam::000000000000:policy/AppManagedPolicy"

###############################################################################
# PoC: no non-default policy version may grant "*:*"
###############################################################################

VERSIONS=$(awslocal iam list-policy-versions \
  --policy-arn "$POLICY_ARN" \
  --query 'Versions[?IsDefaultVersion==`false`].VersionId' \
  --output text 2>/dev/null || true)

for VID in $VERSIONS; do
  DOC=$(awslocal iam get-policy-version \
    --policy-arn "$POLICY_ARN" \
    --version-id "$VID" \
    --query 'PolicyVersion.Document' \
    --output json 2>/dev/null || echo "{}")
  if echo "$DOC" | python3 -c "
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
try:
    doc = json.loads(urllib.parse.unquote(raw))
except Exception:
    doc = json.loads(raw)
for s in doc.get('Statement', []):
    actions = s.get('Action', [])
    if isinstance(actions, str):
        actions = [actions]
    resources = s.get('Resource', [])
    if isinstance(resources, str):
        resources = [resources]
    if s.get('Effect') == 'Allow' and ('*' in actions) and ('*' in resources):
        sys.exit(1)
sys.exit(0)
" 2>/dev/null; then
    : # version is safe
  else
    echo "FAIL [PoC]: Non-default policy version $VID still grants wildcard admin." >&2
    exit 1
  fi
done
echo "PASS [PoC]: No non-default policy version grants '*:*'."

###############################################################################
# PoC 2: app-user must not have iam:SetDefaultPolicyVersion
###############################################################################

INLINE_POLICIES=$(awslocal iam list-user-policies \
  --user-name app-user \
  --query 'PolicyNames' \
  --output json 2>/dev/null || echo "[]")

HAS_SET_DEFAULT="false"
for PNAME in $(echo "$INLINE_POLICIES" | python3 -c "import sys,json; [print(p) for p in json.load(sys.stdin)]" 2>/dev/null); do
  PDOC=$(awslocal iam get-user-policy \
    --user-name app-user \
    --policy-name "$PNAME" \
    --query 'PolicyDocument' \
    --output json 2>/dev/null || echo "{}")
  if echo "$PDOC" | python3 -c "
import sys, json, urllib.parse
raw = sys.stdin.read().strip()
try:
    doc = json.loads(urllib.parse.unquote(raw))
except Exception:
    doc = json.loads(raw)
for s in doc.get('Statement', []):
    if s.get('Effect') == 'Allow':
        actions = s.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        if any(a in ('*', 'iam:*', 'iam:SetDefaultPolicyVersion') for a in actions):
            sys.exit(1)
sys.exit(0)
" 2>/dev/null; then
    : # safe
  else
    HAS_SET_DEFAULT="true"
  fi
done

if [ "$HAS_SET_DEFAULT" = "true" ]; then
  echo "FAIL [PoC]: app-user still has iam:SetDefaultPolicyVersion." >&2
  exit 1
fi
echo "PASS [PoC]: app-user does not have iam:SetDefaultPolicyVersion."

###############################################################################
# Regression: app-user must still exist and managed policy must be attached
###############################################################################

ATTACHED=$(awslocal iam list-attached-user-policies \
  --user-name app-user \
  --query 'AttachedPolicies[].PolicyArn' \
  --output text 2>/dev/null || true)

if echo "$ATTACHED" | grep -q "AppManagedPolicy"; then
  echo "PASS [Regression]: AppManagedPolicy still attached to app-user."
  exit 0
fi

echo "FAIL [Regression]: AppManagedPolicy is no longer attached to app-user." >&2
exit 1
