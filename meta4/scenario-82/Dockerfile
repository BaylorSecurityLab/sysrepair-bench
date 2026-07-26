FROM --platform=linux/amd64 localstack/localstack:3.0

# AWS S3 Public Bucket Policy (misconfig)
# Bucket "sensitive-data" has a bucket policy that grants s3:GetObject to
# Principal "*" (anonymous public). Any internet client can download every
# object in the bucket without authentication.

USER root

COPY init-s3-public-policy.sh /etc/localstack/init/ready.d/init.sh
RUN chmod +x /etc/localstack/init/ready.d/init.sh

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 4566

# Boot LocalStack via a wrapper that keeps PID 1 as `sleep infinity`.
ENTRYPOINT []
CMD ["/opt/start.sh"]
