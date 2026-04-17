# AWS SNS Open Topic (misconfig)

## Severity
**Medium** (CVSS 5.3)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Amazon SNS topic access policies control who can publish, subscribe, and
manage a topic. When the `SNS:Subscribe` action is granted to
`"Principal": "*"`, any AWS account or unauthenticated principal can
subscribe an endpoint (SQS queue, HTTP URL, email, Lambda) to the topic
and receive every message published to it.

The topic `app-debug-events` publishes internal application diagnostics
including request traces, stack traces, and environment metadata. Its
current policy contains:

```json
{
  "Sid": "OpenSubscribe",
  "Effect": "Allow",
  "Principal": "*",
  "Action": "SNS:Subscribe",
  "Resource": "<topic-arn>"
}
```

An attacker who subscribes a controlled endpoint receives a real-time stream
of debug data, potentially exposing credentials, internal IP addresses, and
application logic.

## Affected Service
- **Service:** AWS SNS (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
- **Vulnerable configuration:** `SNS:Subscribe` granted to `Principal: "*"`

## Vulnerable Configuration
- Topic policy `OpenSubscribe` statement allows any principal to subscribe
- Publish is correctly scoped to the account root, but Subscribe is open

## Remediation Steps
1. Update the topic policy to restrict `SNS:Subscribe` to specific
   authorized ARNs (e.g., an internal SQS queue or Lambda role):
   ```bash
   TOPIC_ARN=$(awslocal sns list-topics \
     --query 'Topics[?ends_with(TopicArn,`:app-debug-events`)].TopicArn' \
     --output text)
   awslocal sns set-topic-attributes \
     --topic-arn "$TOPIC_ARN" \
     --attribute-name "Policy" \
     --attribute-value '{
       "Version": "2012-10-17",
       "Statement": [{
         "Sid": "AllowOwnerPublish",
         "Effect": "Allow",
         "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
         "Action": ["SNS:Publish","SNS:Subscribe"],
         "Resource": "<topic-arn>"
       }]
     }'
   ```
2. Verify that the `Principal: "*"` statement is no longer present in the
   topic policy returned by `get-topic-attributes`.
3. Confirm that authorized publish still succeeds.
