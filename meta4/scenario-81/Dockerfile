FROM --platform=linux/amd64 localstack/localstack:3.0

# AWS SSM Plaintext Parameters (misconfig)
# Secrets are stored as SSM Parameter type "String" (plaintext) instead of
# "SecureString" (KMS-encrypted). Anyone with ssm:GetParameter can read the
# secret value in cleartext from the API response and CloudTrail logs.

USER root

COPY init-ssm-plaintext.sh /etc/localstack/init/ready.d/init.sh
RUN chmod +x /etc/localstack/init/ready.d/init.sh

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 4566

# Boot LocalStack via a wrapper that keeps PID 1 as `sleep infinity`.
ENTRYPOINT []
CMD ["/opt/start.sh"]
