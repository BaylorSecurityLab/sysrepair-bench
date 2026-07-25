FROM ubuntu:25.10
# Scenario 50: World-writable web document root
# CWE-732: Incorrect Permission Assignment for Critical Resource
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create web content
RUN echo '<html><body><h1>Company Website</h1><p>Welcome to our site.</p></body></html>' > /var/www/html/index.html && \
    echo '<?php echo "Status: OK"; ?>' > /var/www/html/status.php 2>/dev/null; true

# Make web document root world-writable (vulnerable)
RUN chmod -R 777 /var/www/html


EXPOSE 80
# Boot the vulnerable service, then hold the container open with `sleep
# infinity` (paired with the `.preserve-cmd` marker). `-g 'daemon off;'` is
# dropped so nginx daemonises and control reaches the `exec`, which keeps PID 1
# stable: an agent restarting nginx cannot kill the container, and the site is
# genuinely LIVE while the document root is re-permissioned - so a chmod that
# makes the content unreadable to www-data is caught for real.
CMD ["/bin/bash", "-c", "nginx && exec sleep infinity"]
