#!/bin/bash
# Init: create SNS topic with an open subscription policy
set -eu

echo "[init] Waiting for LocalStack to be ready..."
until awslocal sts get-caller-identity >/dev/null 2>&1; do sleep 1; done
echo "[init] LocalStack ready."

TOPIC_ARN=$(awslocal sns create-topic \
  --name "app-debug-events" \
  --query 'TopicArn' \
  --output text)

echo "[init] Created topic: $TOPIC_ARN"

# Apply an open policy: any AWS principal can Subscribe
awslocal sns set-topic-attributes \
  --topic-arn "$TOPIC_ARN" \
  --attribute-name "Policy" \
  --attribute-value "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Sid\": \"AllowOwnerPublish\",
        \"Effect\": \"Allow\",
        \"Principal\": {\"AWS\": \"arn:aws:iam::000000000000:root\"},
        \"Action\": \"SNS:Publish\",
        \"Resource\": \"$TOPIC_ARN\"
      },
      {
        \"Sid\": \"OpenSubscribe\",
        \"Effect\": \"Allow\",
        \"Principal\": \"*\",
        \"Action\": \"SNS:Subscribe\",
        \"Resource\": \"$TOPIC_ARN\"
      }
    ]
  }"

echo "[init] Done. Topic app-debug-events created with open SNS:Subscribe policy."
