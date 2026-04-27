FROM --platform=linux/amd64 localstack/localstack:3.0

# AWS Lambda Privilege Escalation (design flaw)
# A Lambda execution role holds lambda:* + iam:PassRole with no resource
# condition. An attacker who can invoke the function (or update its code) can
# pass any role — including an admin role — escalating to full administrator.

USER root

COPY init-lambda-privesc.sh /etc/localstack/init/ready.d/init.sh
RUN chmod +x /etc/localstack/init/ready.d/init.sh


EXPOSE 4566
