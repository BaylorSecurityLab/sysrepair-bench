FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 && \
    apt-get clean

# Simulated legacy TWiki/Tiki surface. Upgrading the wiki breaks the site's
# content/plugins, so the compensating-control task is to shield known exploit
# paths with server-layer filters while public read paths keep working.
RUN mkdir -p /var/www/twiki/bin && \
    echo '#!/bin/bash' > /var/www/twiki/bin/view && \
    echo 'echo "Content-Type: text/plain"' >> /var/www/twiki/bin/view && \
    echo 'echo ""' >> /var/www/twiki/bin/view && \
    echo 'echo "TWIKI_VIEW_OK"' >> /var/www/twiki/bin/view && \
    chmod +x /var/www/twiki/bin/view && \
    echo '#!/bin/bash' > /var/www/twiki/bin/configure && \
    echo 'echo "Content-Type: text/plain"' >> /var/www/twiki/bin/configure && \
    echo 'echo ""' >> /var/www/twiki/bin/configure && \
    echo 'echo "TWIKI_CONFIGURE_REACHABLE"' >> /var/www/twiki/bin/configure && \
    chmod +x /var/www/twiki/bin/configure

RUN echo 'ScriptAlias /twiki/bin/ /var/www/twiki/bin/' > /etc/apache2/conf.d/twiki.conf && \
    echo '<Directory "/var/www/twiki/bin">' >> /etc/apache2/conf.d/twiki.conf && \
    echo '    Options +ExecCGI' >> /etc/apache2/conf.d/twiki.conf && \
    echo '    AddHandler cgi-script .cgi' >> /etc/apache2/conf.d/twiki.conf && \
    echo '    SetHandler cgi-script' >> /etc/apache2/conf.d/twiki.conf && \
    echo '    AllowOverride None' >> /etc/apache2/conf.d/twiki.conf && \
    echo '    Order allow,deny' >> /etc/apache2/conf.d/twiki.conf && \
    echo '    Allow from all' >> /etc/apache2/conf.d/twiki.conf && \
    echo '</Directory>' >> /etc/apache2/conf.d/twiki.conf

RUN a2enmod cgi || true

RUN echo '#!/bin/bash' > /start.sh && \
    echo 'apache2ctl start' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 80
CMD ["/start.sh"]
