FROM ubuntu:rolling
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

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
