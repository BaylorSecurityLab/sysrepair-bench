FROM navig/ubuntu:8.04

# Fix old repository URLs
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install Apache, PHP5 CGI, and related packages
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apache2 \
        php5-cgi \
        libapache2-mod-php5 && \
    apt-get clean

# Enable CGI module
RUN a2enmod cgi || true
RUN a2enmod actions || true

# Create the CGI-bin symlink for php-cgi
RUN ln -sf /usr/bin/php-cgi /usr/lib/cgi-bin/php

# Configure Apache to handle .php files via CGI
RUN echo '<Directory "/usr/lib/cgi-bin">' > /etc/apache2/conf.d/php-cgi.conf && \
    echo '    AllowOverride None' >> /etc/apache2/conf.d/php-cgi.conf && \
    echo '    Options +ExecCGI' >> /etc/apache2/conf.d/php-cgi.conf && \
    echo '    Order allow,deny' >> /etc/apache2/conf.d/php-cgi.conf && \
    echo '    Allow from all' >> /etc/apache2/conf.d/php-cgi.conf && \
    echo '</Directory>' >> /etc/apache2/conf.d/php-cgi.conf && \
    echo 'ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/' >> /etc/apache2/conf.d/php-cgi.conf

# Create a test PHP file accessible via CGI
RUN echo '<?php echo "PHP CGI is working"; ?>' > /usr/lib/cgi-bin/test.php && \
    chmod +x /usr/lib/cgi-bin/test.php

# Also create a standard PHP page in the web root
RUN echo '<?php phpinfo(); ?>' > /var/www/info.php

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'apache2ctl start' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 80

CMD ["/start.sh"]
