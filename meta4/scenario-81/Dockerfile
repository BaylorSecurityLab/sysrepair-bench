FROM --platform=linux/amd64 localstack/localstack:3.0

# AWS SSM Plaintext Parameters (misconfig)
# Secrets are stored as SSM Parameter type "String" (plaintext) instead of
# "SecureString" (KMS-encrypted). Anyone with ssm:GetParameter can read the
# secret value in cleartext from the API response and CloudTrail logs.

USER root

COPY init-ssm-plaintext.sh /etc/localstack/init/ready.d/init.sh
RUN chmod +x /etc/localstack/init/ready.d/init.sh

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 4566
