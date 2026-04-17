#!/bin/bash
# Init: provision IAM user + managed policy with an overpermissive version 2
set -eu

echo "[init] Waiting for LocalStack to be ready..."
until awslocal sts get-caller-identity >/dev/null 2>&1; do sleep 1; done
echo "[init] LocalStack ready."

# Create a managed policy — v1 is restrictive (S3 read-only)
POLICY_ARN=$(awslocal iam create-policy \
  --policy-name "AppManagedPolicy" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:GetObject","s3:ListBucket"],
      "Resource": "*"
    }]
  }' \
  --query 'Policy.Arn' --output text)

echo "[init] Created policy: $POLICY_ARN (v1 = S3 read-only, default)"

# Create v2 — full admin wildcard
awslocal iam create-policy-version \
  --policy-arn "$POLICY_ARN" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }]
  }' \
  --no-set-as-default

echo "[init] Created policy v2 (full admin, non-default)"

# Create IAM user that can escalate via SetDefaultPolicyVersion
awslocal iam create-user --user-name "app-user"

awslocal iam attach-user-policy \
  --user-name "app-user" \
  --policy-arn "$POLICY_ARN"

# Also give app-user the ability to set the default policy version (the vuln)
awslocal iam put-user-policy \
  --user-name "app-user" \
  --policy-name "AllowPolicyVersionSwitch" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": "iam:SetDefaultPolicyVersion",
      "Resource": "*"
    }]
  }'

echo "[init] Done. app-user attached to AppManagedPolicy (v1 default, v2 escalation path available)."
