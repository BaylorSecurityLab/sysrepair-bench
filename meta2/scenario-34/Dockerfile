FROM sysrepair/meta2-hardy:latest
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apache2 \
        php5-cgi \
        curl && \
    apt-get clean

RUN a2enmod actions || true
RUN a2enmod cgi || true

RUN ln -sf /usr/bin/php-cgi /usr/lib/cgi-bin/php

# php5-cgi 5.2.4 is vulnerable to CVE-2012-1823: a query string with no '=' and a
# leading dash is passed to php-cgi as command-line flags. Routing .php through
# php-cgi via an Action handler reproduces the exploitable path:
#   GET /cgi-bin/legacy.php?-s  -> php-cgi -s -> source disclosure (and ?-d... -> RCE)
RUN printf '%s\n' \
    'ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/' \
    '<Directory "/usr/lib/cgi-bin">' \
    '    AllowOverride None' \
    '    Options +ExecCGI' \
    '    Order allow,deny' \
    '    Allow from all' \
    '    AddHandler application/x-httpd-php .php' \
    '    Action application/x-httpd-php /cgi-bin/php' \
    '</Directory>' \
    > /etc/apache2/conf.d/php-cgi.conf

# Legacy "Mutillidae-style" app that REQUIRES PHP-CGI and cannot be upgraded.
# The compensating-control scenario requires this app to stay functional after mitigation.
RUN echo '<?php echo "LEGACY_APP_OK:".PHP_VERSION; ?>' > /usr/lib/cgi-bin/legacy.php && \
    chmod +x /usr/lib/cgi-bin/legacy.php

# Boot wrapper: start apache in the foreground-daemon mode, then keep PID 1 as
# `sleep infinity` so an agent restarting apache can never kill the container.
# The live, vulnerable php-cgi surface is already serving when the agent starts.
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'apache2ctl start' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 80
CMD ["/start.sh"]
