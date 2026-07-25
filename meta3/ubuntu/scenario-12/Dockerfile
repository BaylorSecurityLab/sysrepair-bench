FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|mirrors.kernel.org|g; s|security.ubuntu.com|mirrors.kernel.org|g' /etc/apt/sources.list && \
    apt-get update && apt-get clean

# Install Ruby (for WEBrick) and networking utilities for verification
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ruby \
        curl \
        iproute \
        net-tools \
    && apt-get clean

# Deploy the admin application bound to 0.0.0.0 (vulnerable configuration)
RUN mkdir -p /opt
COPY scenario-12/admin_app.rb /opt/admin_app.rb


COPY scenario-12/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3500

# Boot wrapper (see entrypoint.sh + .preserve-cmd): the launcher lives in a file
# so PID 1's argv is just "/entrypoint.sh" -- otherwise pkill -f admin_app.rb
# would match the docker-init PID 1 and kill the container.
CMD ["/entrypoint.sh"]
