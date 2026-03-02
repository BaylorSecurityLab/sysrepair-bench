FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

# Fix old repository sources
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install Apache 2.2
RUN apt-get update && \
    apt-get install -y apache2 && \
    apt-get clean

# Enable WebDAV modules
RUN a2enmod dav && \
    a2enmod dav_fs

# Create DAV directory writable by Apache
RUN mkdir -p /var/www/dav && \
    chown www-data:www-data /var/www/dav

# Create DAV lock directory
RUN mkdir -p /var/lock/apache2/dav && \
    chown www-data:www-data /var/lock/apache2/dav

# Configure WebDAV without authentication
RUN cat > /etc/apache2/sites-available/dav <<'DAVCONF'
Alias /dav /var/www/dav
<Directory /var/www/dav>
    Dav On
    Options Indexes
    Order allow,deny
    Allow from all
</Directory>
DavLockDB /var/lock/apache2/dav/DavLock
DAVCONF

# Enable the DAV site config
RUN ln -sf /etc/apache2/sites-available/dav /etc/apache2/sites-enabled/dav

# Create a basic index page
RUN echo '<html><body><h1>Welcome to the server</h1></body></html>' > /var/www/index.html

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'apache2ctl start' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]
