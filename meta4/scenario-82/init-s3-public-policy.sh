#!/bin/bash
# Init: create S3 bucket with a public-read bucket policy
set -eu

echo "[init] Waiting for LocalStack to be ready..."
until awslocal sts get-caller-identity >/dev/null 2>&1; do sleep 1; done
echo "[init] LocalStack ready."

awslocal s3api create-bucket --bucket sensitive-data

# Upload a sample object so there is something to (publicly) read
echo "customer_id,email,ssn" | awslocal s3 cp - s3://sensitive-data/customers.csv

# Apply a bucket policy granting public read to everyone
awslocal s3api put-bucket-policy \
  --bucket sensitive-data \
  --policy '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::sensitive-data/*"
    }]
  }'

echo "[init] Done. Bucket sensitive-data created with public-read policy."
