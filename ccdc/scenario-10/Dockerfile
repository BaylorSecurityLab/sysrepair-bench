FROM ubuntu:25.10
# Scenario 10: Nginx autoindex on (directory listing)
# CWE-548: Exposure of Information Through Directory Listing
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable autoindex (directory listing) in default site
RUN mkdir -p /etc/nginx/conf.d && \
    echo 'server { listen 80 default_server; root /var/www/html; index index.html; location / { autoindex on; try_files $uri $uri/ =404; } }' > /etc/nginx/conf.d/default.conf && \
    rm -f /etc/nginx/sites-enabled/default

# Create files but no index in a subdirectory
RUN mkdir -p /var/www/html/files && \
    echo "secret" > /var/www/html/files/passwords.txt && \
    echo "config" > /var/www/html/files/database.conf && \
    echo '<html><body><h1>Main Page</h1></body></html>' > /var/www/html/index.html


EXPOSE 80

# Boot the vulnerable service, then hold the container open with `sleep
# infinity`. Paired with the `.preserve-cmd` marker so the harness keeps this
# CMD instead of replacing it. `nginx` without `-g "daemon off;"` daemonizes,
# so control reaches the `exec`.
#   1. nginx must ALREADY BE RUNNING when the agent is handed the box, so a
#      config-only fix leaves the live server vulnerable and verify.sh fails.
#   2. PID 1 must NOT be nginx - restarting the service would otherwise kill the
#      container. `exec sleep infinity` keeps a stable PID 1.
CMD ["/bin/bash", "-c", "nginx && exec sleep infinity"]
