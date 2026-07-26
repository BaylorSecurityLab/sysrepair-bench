FROM --platform=linux/amd64 ubuntu:22.04

# CWE-312: a database password is baked into the image as a WORLD-READABLE
# plaintext file (/opt/app/app.env, mode 0644). It persists in every image
# layer and is trivially extractable by any user/process in the container and by
# anyone who pulls the image.
#
# (Previously this scenario used `ENV DB_PASSWORD=...`. A baked image ENV is
# injected by Docker into every process environment and /proc/1/environ and
# CANNOT be removed by an in-container remediation, which made the scenario
# unsolvable inside the running container. The world-readable secret file models
# the same cleartext-storage weakness while being remediable at runtime.)

RUN apt-get update && \
    apt-get install -y --no-install-recommends bash && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/app && \
    echo 'DB_PASSWORD=P@ssw0rd_2024' > /opt/app/app.env && \
    chmod 644 /opt/app/app.env

COPY app.sh /opt/app/app.sh
RUN chmod +x /opt/app/app.sh


CMD ["/opt/app/app.sh"]
