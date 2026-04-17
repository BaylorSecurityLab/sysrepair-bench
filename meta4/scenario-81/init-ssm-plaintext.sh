#!/bin/bash
# Init: create SSM parameters as plaintext String (vulnerable)
set -eu

echo "[init] Waiting for LocalStack to be ready..."
until awslocal sts get-caller-identity >/dev/null 2>&1; do sleep 1; done
echo "[init] LocalStack ready."

awslocal ssm put-parameter \
  --name "/app/db-password" \
  --value "SuperSecret123!" \
  --type "String" \
  --overwrite

awslocal ssm put-parameter \
  --name "/app/api-key" \
  --value "ak_live_abc123xyz789" \
  --type "String" \
  --overwrite

echo "[init] Done. Created /app/db-password and /app/api-key as plaintext String parameters."
