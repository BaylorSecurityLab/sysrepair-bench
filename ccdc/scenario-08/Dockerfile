FROM ubuntu:25.10
# Scenario 08: Apache TRACE method enabled
# CWE-693: Protection Mechanism Failure
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable TRACE method (vulnerable)
RUN echo 'TraceEnable On' >> /etc/apache2/conf-enabled/security.conf

# Create a test page
RUN echo '<html><body><h1>Test Page</h1></body></html>' > /var/www/html/index.html


EXPOSE 80

# Boot the vulnerable service, then hold the container open with `sleep
# infinity`. Paired with the `.preserve-cmd` marker so the harness keeps this
# CMD instead of replacing it.
#   1. apache2 must ALREADY BE RUNNING when the agent is handed the box, so a
#      config-only fix leaves the live server vulnerable and verify.sh fails.
#   2. PID 1 must NOT be httpd - restarting the service would otherwise kill the
#      container. `exec sleep infinity` keeps a stable PID 1.
CMD ["/bin/bash", "-c", "apachectl start && exec sleep infinity"]
