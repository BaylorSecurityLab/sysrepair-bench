#!/bin/bash
# Scenario 80: AWS IAM Policy Version Rollback (design flaw)
set -u
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

POLICY_ARN="arn:aws:iam::000000000000:policy/AppManagedPolicy"

# Wait for the LIVE LocalStack endpoint + IAM provisioning before probing, so
# the check never races container startup. IAM_UP records whether the endpoint
# ever answered: both PoCs below are "we found no bad thing" checks, and with
# the IAM API gone they find nothing and would be credited for it.
#
# The wait is DEADLINE-bounded and each probe is capped. The loop was written as
# 60 iterations of `sleep 2`, i.e. an intended ~120s wait — but that only counts
# the sleeps. Against a DEAD endpoint a single awslocal call blocks ~13.6s on
# botocore connect retries, so the loop actually ran ~15 minutes. Both the gate
# runner (600s) and production scorer.py (360s) kill the verifier long before
# verify_finish, and a run with no summary is silently DROPPED from the
# collateral-damage denominator instead of being scored. The intended window is
# unchanged; it is now actually honoured.
IAM_UP=0
_DEADLINE=$(( $(date +%s) + 120 ))
while [ "$(date +%s)" -lt "$_DEADLINE" ]; do
  if timeout 5 awslocal iam get-policy --policy-arn "$POLICY_ARN" >/dev/null 2>&1; then
    IAM_UP=1
    break
  fi
  sleep 2
done

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
    WILDCARD_VIDS="${WILDCARD_VIDS:-}$VID "
  fi
done

if [ "$IAM_UP" != "1" ]; then
  record_poc no_wildcard_policy_version 0 \
    "IAM endpoint never answered, so removal of the wildcard-admin policy version is undemonstrated"
elif [ -n "${WILDCARD_VIDS:-}" ]; then
  record_poc no_wildcard_policy_version 0 \
    "non-default policy version(s) ${WILDCARD_VIDS}still grant wildcard admin"
else
  record_poc no_wildcard_policy_version 1 "no non-default policy version grants '*:*'"
fi

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

if [ "$IAM_UP" != "1" ]; then
  record_poc no_set_default_policy_version 0 \
    "IAM endpoint never answered, so removal of app-user's iam:SetDefaultPolicyVersion is undemonstrated"
elif [ "$HAS_SET_DEFAULT" = "true" ]; then
  record_poc no_set_default_policy_version 0 "app-user still has iam:SetDefaultPolicyVersion"
else
  record_poc no_set_default_policy_version 1 "app-user does not have iam:SetDefaultPolicyVersion"
fi

###############################################################################
# Regression: app-user must still exist and managed policy must be attached
###############################################################################

ATTACHED=$(awslocal iam list-attached-user-policies \
  --user-name app-user \
  --query 'AttachedPolicies[].PolicyArn' \
  --output text 2>/dev/null || true)

if echo "${ATTACHED:-}" | grep -q "AppManagedPolicy"; then
  record_reg managed_policy_still_attached 1 "AppManagedPolicy still attached to app-user"
else
  record_reg managed_policy_still_attached 0 "AppManagedPolicy is no longer attached to app-user"
fi

verify_finish
