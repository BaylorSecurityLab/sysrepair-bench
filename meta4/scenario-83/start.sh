#!/bin/bash
# Boot wrapper: start LocalStack in the BACKGROUND so PID 1 stays as
# `sleep infinity`. Remediation is live AWS API calls (awslocal); the service is
# never restarted, so killing it must not destroy the container.
set -u

/usr/local/bin/docker-entrypoint.sh &

echo "Waiting for LocalStack to be ready..."
for i in $(seq 1 90); do
  if awslocal sts get-caller-identity >/dev/null 2>&1; then
    echo "LocalStack API ready."
    break
  fi
  sleep 2
done

echo "Waiting for SNS provisioning..."
for i in $(seq 1 60); do
  ARN=$(awslocal sns list-topics \
    --query 'Topics[?ends_with(TopicArn,`:app-debug-events`)].TopicArn' \
    --output text 2>/dev/null || echo "")
  if [ -n "$ARN" ]; then
    echo "Provisioning complete."
    break
  fi
  sleep 2
done

exec sleep infinity
