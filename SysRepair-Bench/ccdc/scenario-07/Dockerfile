FROM ubuntu:rolling
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

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]
