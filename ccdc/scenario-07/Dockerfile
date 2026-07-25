FROM ubuntu:25.10
# Scenario 07: Apache directory listing enabled
# CWE-548: Exposure of Information Through Directory Listing
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable directory listing (Options Indexes)
RUN sed -i 's/Options -Indexes/Options Indexes FollowSymLinks/' /etc/apache2/conf-enabled/security.conf 2>/dev/null; \
    sed -i 's/Options -Indexes/Options Indexes FollowSymLinks/' /etc/apache2/apache2.conf 2>/dev/null; \
    # Ensure Indexes is set in the default site
    sed -i 's/Options -Indexes +FollowSymLinks/Options Indexes FollowSymLinks/' /etc/apache2/apache2.conf 2>/dev/null

# Create some files but no index.html in a subdirectory
RUN mkdir -p /var/www/html/data && \
    echo "secret data" > /var/www/html/data/credentials.txt && \
    echo "config info" > /var/www/html/data/config.txt && \
    echo '<html><body><h1>Main Page</h1></body></html>' > /var/www/html/index.html


EXPOSE 80

# Boot the vulnerable service, then hold the container open with `sleep
# infinity`. Paired with the `.preserve-cmd` marker so the harness keeps this
# CMD instead of replacing it.
#   1. apache2 must ALREADY BE RUNNING when the agent is handed the box, so a
#      config-only fix leaves the live server vulnerable and verify.sh fails.
#   2. PID 1 must NOT be httpd - restarting the service would otherwise kill the
#      container. `exec sleep infinity` keeps a stable PID 1.
CMD ["/bin/bash", "-c", "apachectl start && exec sleep infinity"]
