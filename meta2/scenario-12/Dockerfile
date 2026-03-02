FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

# Fix old repository sources
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install Apache 2.2
RUN apt-get update && \
    apt-get install -y apache2 && \
    apt-get clean

# Configure /doc alias to expose /usr/share/doc with directory indexing
RUN cat > /etc/apache2/conf.d/doc <<'DOCCONF'
Alias /doc /usr/share/doc
<Directory /usr/share/doc>
    Options Indexes FollowSymLinks
    Order allow,deny
    Allow from all
</Directory>
DOCCONF

# Create a basic index page
RUN echo '<html><body><h1>Welcome to the server</h1></body></html>' > /var/www/index.html

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'apache2ctl start' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]
