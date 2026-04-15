FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g; s|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y curl ca-certificates && \
    apt-get clean

# Install Chef 13.8.5 via Omnibus
RUN curl -L https://omnitruck.chef.io/install.sh | bash -s -- -v 13.8.5

# Build context is meta3/ubuntu/ -- run: docker build -f scenario-15/Dockerfile -t meta3u-s15 .
COPY shared/cookbooks /cookbooks
COPY scenario-15/solo.rb /solo.rb
COPY scenario-15/scenario.json /scenario.json
RUN chef-solo -c /solo.rb -j /scenario.json

# Install stunnel4 for the compensating control remediation path
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y stunnel4 openssl netcat && \
    apt-get clean

# Seed stunnel configuration directory (agent populates content during remediation)
RUN mkdir -p /etc/stunnel

# Generate a self-signed TLS certificate for stunnel (used after remediation)
RUN openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/stunnel/stunnel.pem \
    -out /etc/stunnel/stunnel.pem \
    -subj "/CN=localhost" 2>/dev/null && \
    chmod 600 /etc/stunnel/stunnel.pem

COPY scenario-15/verify.sh /verify.sh
COPY scenario-15/entrypoint.sh /entrypoint.sh
RUN chmod +x /verify.sh /entrypoint.sh

# Expose stunnel TLS port (post-remediation) and raw IRC (pre-remediation)
EXPOSE 6667 6697

CMD ["/entrypoint.sh"]
