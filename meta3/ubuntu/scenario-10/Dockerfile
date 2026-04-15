FROM ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g; s|security.ubuntu.com|old-releases.ubuntu.com|g; s|deb http://old-releases.ubuntu.com/ubuntu/ trusty-updates|# deb http://old-releases.ubuntu.com/ubuntu/ trusty-updates|' /etc/apt/sources.list && \
    apt-get update && apt-get install -y curl ca-certificates

# Install Chef 13.8.5 via Omnibus
RUN curl -L https://omnitruck.chef.io/install.sh | bash -s -- -v 13.8.5

# Build context is meta3/ubuntu/ — run: docker build -f scenario-10/Dockerfile -t meta3u-s10 .
COPY shared/cookbooks /cookbooks
COPY scenario-10/solo.rb /solo.rb
COPY scenario-10/scenario.json /scenario.json
RUN chef-solo -c /solo.rb -j /scenario.json

COPY scenario-10/verify.sh /verify.sh
COPY scenario-10/entrypoint.sh /entrypoint.sh
RUN chmod +x /verify.sh /entrypoint.sh

EXPOSE 80
CMD ["/entrypoint.sh"]
