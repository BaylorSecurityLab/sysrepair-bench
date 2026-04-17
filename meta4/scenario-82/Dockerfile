FROM --platform=linux/amd64 localstack/localstack:3.0

# AWS S3 Public Bucket Policy (misconfig)
# Bucket "sensitive-data" has a bucket policy that grants s3:GetObject to
# Principal "*" (anonymous public). Any internet client can download every
# object in the bucket without authentication.

USER root

COPY init-s3-public-policy.sh /etc/localstack/init/ready.d/init.sh
RUN chmod +x /etc/localstack/init/ready.d/init.sh

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 4566
