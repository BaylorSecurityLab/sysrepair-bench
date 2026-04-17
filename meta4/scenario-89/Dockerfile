FROM --platform=linux/amd64 ubuntu:22.04

# ARG value used in a RUN command is captured in the image layer diff.
# Even though ARG does not persist in the final image ENV, the value is
# recoverable from the layer via `docker history --no-trunc` or by
# exporting and inspecting the image tarball.

ARG SECRET_TOKEN=ghp_abc123def456

RUN apt-get update && \
    apt-get install -y --no-install-recommends bash && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/app && \
    echo "token=${SECRET_TOKEN}" > /etc/app/config.ini

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["bash", "-c", "echo 'App config:'; cat /etc/app/config.ini; exec sleep infinity"]
