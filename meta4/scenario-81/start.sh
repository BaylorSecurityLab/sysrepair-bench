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

echo "Waiting for SSM provisioning..."
for i in $(seq 1 60); do
  if awslocal ssm get-parameter --name /app/db-password >/dev/null 2>&1; then
    echo "Provisioning complete."
    break
  fi
  sleep 2
done

exec sleep infinity
