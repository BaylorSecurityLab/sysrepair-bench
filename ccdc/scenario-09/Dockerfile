FROM ubuntu:rolling
# Scenario 09: Nginx server_tokens on / version disclosure
# CWE-200: Exposure of Sensitive Information
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure server_tokens is on (version disclosure)
RUN sed -i '/http {/a\\tserver_tokens on;' /etc/nginx/nginx.conf 2>/dev/null || \
    echo 'server_tokens on;' >> /etc/nginx/nginx.conf

# Create a test page
RUN echo '<html><body><h1>Test Page</h1></body></html>' > /var/www/html/index.html

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
