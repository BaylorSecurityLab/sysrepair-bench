FROM --platform=linux/amd64 localstack/localstack:3.0

# AWS IAM Policy Version Rollback (design flaw)
# An IAM managed policy has multiple versions: v1 is restrictive (default)
# but v2 grants full admin ("*:*"). Any principal with iam:SetDefaultPolicyVersion
# can silently escalate to admin by switching the default back to v2.

USER root

COPY init-iam-policy-rollback.sh /etc/localstack/init/ready.d/init.sh
RUN chmod +x /etc/localstack/init/ready.d/init.sh


EXPOSE 4566
