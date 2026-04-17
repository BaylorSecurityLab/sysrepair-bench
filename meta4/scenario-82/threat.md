# AWS S3 Public Bucket Policy (misconfig)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CWE-284: Improper Access Control

## Description
Amazon S3 bucket policies control who can perform operations on a bucket and
its objects. A policy statement with `"Principal": "*"` applies to any
unauthenticated (anonymous) requester on the internet. When such a statement
grants `s3:GetObject`, every object in the bucket is publicly downloadable
without credentials — a common source of accidental data leaks.

In this scenario the bucket `sensitive-data` has the following policy:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::sensitive-data/*"
  }]
}
```

Any client on the network can download `customers.csv` (and any other object)
without signing the request:

```bash
curl http://localhost:4566/sensitive-data/customers.csv
```

## Affected Service
- **Service:** AWS S3 (LocalStack 3.0)
- **Port:** 4566/TCP (LocalStack endpoint)
- **Vulnerable configuration:** Bucket policy with `Principal: "*"` and
  `Action: s3:GetObject`

## Vulnerable Configuration
- `sensitive-data` bucket policy allows public anonymous read on all objects
- Block Public Access settings are not enabled

## Remediation Steps
1. Delete the public bucket policy or replace it with a policy scoped to
   specific IAM ARNs:
   ```bash
   awslocal s3api delete-bucket-policy --bucket sensitive-data
   # Or replace with a restricted policy referencing specific IAM roles/users
   ```
2. Enable S3 Block Public Access on the bucket:
   ```bash
   awslocal s3api put-public-access-block \
     --bucket sensitive-data \
     --public-access-block-configuration \
       "BlockPublicAcls=true,IgnorePublicAcls=true,\
BlockPublicPolicy=true,RestrictPublicBuckets=true"
   ```
3. Verify that no statement in the bucket policy contains `"Principal": "*"`.
4. Confirm that authorized IAM principals can still access objects using
   signed requests.
