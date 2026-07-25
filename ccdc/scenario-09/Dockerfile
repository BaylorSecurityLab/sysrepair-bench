FROM ubuntu:25.10
# Scenario 09: Nginx server_tokens on / version disclosure
# CWE-200: Exposure of Sensitive Information
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure server_tokens is on (version disclosure) and avoid duplicates
RUN sed -i '/server_tokens/d' /etc/nginx/nginx.conf && \
    sed -i '/http {/a\\tserver_tokens on;' /etc/nginx/nginx.conf

# Create a test page
RUN echo '<html><body><h1>Test Page</h1></body></html>' > /var/www/html/index.html


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

