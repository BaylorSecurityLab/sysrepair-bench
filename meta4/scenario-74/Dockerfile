FROM --platform=linux/amd64 ubuntu:22.04

# CWE-312: Cleartext Storage of Sensitive Information — world-readable secret
#
# A database password and API key are shipped in the image as a WORLD-READABLE
# plaintext config file (/etc/appsecrets/db.conf, mode 0644). The secret is
# readable by any unprivileged user or co-tenant process in the container
# (`cat /etc/appsecrets/db.conf`) and persists in every image layer, so anyone
# who pulls the image or unpacks its layers recovers it.
#
# (Previously this scenario baked the secrets into image `ENV` instructions.
# A baked image ENV is injected by Docker into every process environment and
# /proc/1/environ and CANNOT be removed by any in-container remediation — only
# an image rebuild removes it — which made the scenario unsolvable inside the
# running container. Moving the secret to a world-readable file models the same
# cleartext-storage weakness (CWE-312) while being remediable at runtime, the
# same reframe applied to meta4/scenario-88 with a distinct secret and path.)

RUN apt-get update && \
    apt-get install -y --no-install-recommends bash && \
    rm -rf /var/lib/apt/lists/*

# Vulnerable: secrets in a world-readable file baked into the image.
RUN mkdir -p /etc/appsecrets && \
    printf 'DB_PASSWORD=SuperSecret123\nAPI_KEY=sk-live-abc123\n' > /etc/appsecrets/db.conf && \
    chmod 644 /etc/appsecrets/db.conf

COPY app.sh /usr/local/bin/appd.sh
RUN chmod +x /usr/local/bin/appd.sh

CMD ["/usr/local/bin/appd.sh"]
