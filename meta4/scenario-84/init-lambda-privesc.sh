#!/bin/bash
# Init: create Lambda function with an overprivileged execution role
set -eu

echo "[init] Waiting for LocalStack to be ready..."
until awslocal sts get-caller-identity >/dev/null 2>&1; do sleep 1; done
echo "[init] LocalStack ready."

# Create the overprivileged Lambda execution role
awslocal iam create-role \
  --role-name "lambda-exec-role" \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach inline policy: lambda:* + unrestricted iam:PassRole (the vuln)
awslocal iam put-role-policy \
  --role-name "lambda-exec-role" \
  --policy-name "LambdaOverprivilegedPolicy" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AllLambda",
        "Effect": "Allow",
        "Action": "lambda:*",
        "Resource": "*"
      },
      {
        "Sid": "UnrestrictedPassRole",
        "Effect": "Allow",
        "Action": "iam:PassRole",
        "Resource": "*"
      }
    ]
  }'

ROLE_ARN=$(awslocal iam get-role \
  --role-name "lambda-exec-role" \
  --query 'Role.Arn' --output text)

echo "[init] Created role: $ROLE_ARN"

# Create a minimal Lambda function (inline zip of a trivial Python handler)
TMPDIR=$(mktemp -d)
cat > "$TMPDIR/index.py" <<'PYEOF'
def handler(event, context):
    return {"statusCode": 200, "body": "ok"}
PYEOF
cd "$TMPDIR" && zip function.zip index.py

awslocal lambda create-function \
  --function-name "app-processor" \
  --runtime "python3.11" \
  --role "$ROLE_ARN" \
  --handler "index.handler" \
  --zip-file "fileb://$TMPDIR/function.zip"

rm -rf "$TMPDIR"

echo "[init] Done. Lambda app-processor created with overprivileged lambda-exec-role."
