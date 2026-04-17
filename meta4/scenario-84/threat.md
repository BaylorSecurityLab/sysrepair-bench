# AWS Lambda Privilege Escalation (design flaw)

## Severity
**High** (CVSS 8.8)

## CVE / CWE
- CWE-269: Improper Privilege Management

## Description
AWS Lambda functions execute under an IAM execution role. When that role
includes `iam:PassRole` without a resource condition, any principal that can
update the function's configuration (e.g., `lambda:UpdateFunctionConfiguration`)
can swap the execution role for an admin role and gain administrator-equivalent
access on the next invocation.

Additionally, `lambda:*` without scope allows the role holder to create or
update Lambda functions and pass arbitrary roles — a well-known privilege
escalation path documented in multiple AWS security assessments.

The role `lambda-exec-role` attached to `app-processor` contains:

```json
{
  "Statement": [
    {"Action": "lambda:*",    "Effect": "Allow", "Resource": "*"},
    {"Action": "iam:PassRole","Effect": "Allow", "Resource": "*"}
  ]
}
```

An attacker with access to this role can call:

```bash
awslocal lambda update-function-configuration \
  --function-name app-processor \
  --role arn:aws:iam::000000000000:role/AdminRole
```

and then invoke the function to execute arbitrary code under the admin role.

## Affected Service
- **Service:** AWS Lambda + IAM (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
- **Vulnerable configuration:** `iam:PassRole` on `Resource: "*"` with no
  condition; `lambda:*` on all resources

## Vulnerable Configuration
- `lambda-exec-role` inline policy grants `iam:PassRole` on `"Resource": "*"`
- No permission boundary on the role to cap maximum privilege

## Remediation Steps
1. Replace the inline policy with a scoped version: restrict `iam:PassRole`
   to a specific resource ARN and add a `StringEquals` condition on
   `iam:PassedToService`:
   ```bash
   awslocal iam put-role-policy \
     --role-name lambda-exec-role \
     --policy-name LambdaOverprivilegedPolicy \
     --policy-document '{
       "Version": "2012-10-17",
       "Statement": [
         {
           "Sid": "ScopedLambda",
           "Effect": "Allow",
           "Action": ["lambda:InvokeFunction","lambda:GetFunction"],
           "Resource": "arn:aws:lambda:us-east-1:000000000000:function:app-processor"
         },
         {
           "Sid": "ScopedPassRole",
           "Effect": "Allow",
           "Action": "iam:PassRole",
           "Resource": "arn:aws:iam::000000000000:role/lambda-exec-role",
           "Condition": {
             "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}
           }
         }
       ]
     }'
   ```
2. Attach a permission boundary to `lambda-exec-role` that caps its
   maximum effective permissions.
3. Verify that `iam:PassRole` on `"Resource": "*"` is no longer present in
   any policy attached to the role.
