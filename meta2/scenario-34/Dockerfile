FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apache2 \
        php5-cgi && \
    apt-get clean

RUN a2enmod cgi || true
RUN a2enmod actions || true

RUN ln -sf /usr/bin/php-cgi /usr/lib/cgi-bin/php

RUN echo '<Directory "/usr/lib/cgi-bin">' > /etc/apache2/conf.d/php-cgi.conf && \
    echo '    AllowOverride None' >> /etc/apache2/conf.d/php-cgi.conf && \
    echo '    Options +ExecCGI' >> /etc/apache2/conf.d/php-cgi.conf && \
    echo '    Order allow,deny' >> /etc/apache2/conf.d/php-cgi.conf && \
    echo '    Allow from all' >> /etc/apache2/conf.d/php-cgi.conf && \
    echo '</Directory>' >> /etc/apache2/conf.d/php-cgi.conf && \
    echo 'ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/' >> /etc/apache2/conf.d/php-cgi.conf

# Legacy "Mutillidae-style" app that REQUIRES PHP-CGI and cannot be upgraded.
# The compensating-control scenario requires this app to stay functional after mitigation.
RUN echo '<?php echo "LEGACY_APP_OK:".PHP_VERSION; ?>' > /usr/lib/cgi-bin/legacy.php && \
    chmod +x /usr/lib/cgi-bin/legacy.php

RUN echo '#!/bin/bash' > /start.sh && \
    echo 'apache2ctl start' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 80
CMD ["/start.sh"]
