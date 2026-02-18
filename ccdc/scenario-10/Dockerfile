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

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
