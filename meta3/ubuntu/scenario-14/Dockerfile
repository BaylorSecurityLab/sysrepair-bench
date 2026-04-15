FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g; s|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    apt-get update && apt-get install -y curl ca-certificates && \
    apt-get clean

# Install Chef 13.8.5 via Omnibus
RUN curl -L https://omnitruck.chef.io/install.sh | bash -s -- -v 13.8.5

# Build context is meta3/ubuntu/ -- run: docker build -f scenario-14/Dockerfile -t meta3u-s14 .
COPY shared/cookbooks /cookbooks
COPY scenario-14/solo.rb /solo.rb
COPY scenario-14/scenario.json /scenario.json
RUN chef-solo -c /solo.rb -j /scenario.json

# Write a modules.conf that loads mod_copy -- the vulnerable state.
# Compensating remediation: agent must comment out the LoadModule line,
# but must NOT upgrade ProFTPD (pinned at 1.3.5 for legacy client compatibility).
RUN mkdir -p /opt/proftpd/etc && \
    printf '# ProFTPD module configuration\n# LoadModule directives enable optional modules.\n\nLoadModule mod_copy.c\n' \
        > /opt/proftpd/etc/modules.conf

# Patch the main proftpd.conf to include modules.conf
RUN if [ -f /opt/proftpd/etc/proftpd.conf ]; then \
        grep -q 'Include.*modules.conf' /opt/proftpd/etc/proftpd.conf || \
        echo 'Include /opt/proftpd/etc/modules.conf' >> /opt/proftpd/etc/proftpd.conf; \
    fi

COPY scenario-14/verify.sh /verify.sh
COPY scenario-14/entrypoint.sh /entrypoint.sh
RUN chmod +x /verify.sh /entrypoint.sh

EXPOSE 21

CMD ["/entrypoint.sh"]
