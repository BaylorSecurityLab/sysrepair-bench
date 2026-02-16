FROM ubuntu:rolling
# Scenario 06: Apache ServerTokens Full / ServerSignature On
# CWE-200: Exposure of Sensitive Information
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create vulnerable Apache configuration - expose server version info
RUN echo 'ServerTokens Full' >> /etc/apache2/conf-enabled/security.conf && \
    echo 'ServerSignature On' >> /etc/apache2/conf-enabled/security.conf

# Create a test page for functionality
RUN echo '<html><body><h1>Test Page</h1></body></html>' > /var/www/html/index.html

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]
