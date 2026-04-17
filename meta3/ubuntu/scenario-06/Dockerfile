FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|mirrors.kernel.org|g; s|security.ubuntu.com|mirrors.kernel.org|g' /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl ca-certificates wget \
        apache2 \
        mysql-server mysql-client \
        gcc make build-essential \
        libxml2-dev libcurl4-openssl-dev libpcre3-dev libbz2-dev libjpeg-dev \
        libpng12-dev libfreetype6-dev libt1-dev libmcrypt-dev libmhash-dev \
        freetds-dev libmysqlclient-dev unixodbc-dev \
        libxslt1-dev apache2-dev && \
    apt-get clean

# ---------- PHP 5.4.5 from source ----------
RUN mkdir -pv /usr/include/freetype2/freetype && \
    ln -sf /usr/include/freetype2/freetype.h /usr/include/freetype2/freetype/freetype.h

RUN cd /tmp && \
    wget -q http://museum.php.net/php5/php-5.4.5.tar.gz && \
    wget -q -O libxml29_compat.patch "https://mail.gnome.org/archives/xml/2012-August/txtbgxGXAvz4N.txt" && \
    tar xzf php-5.4.5.tar.gz && \
    cd php-5.4.5 && \
    patch -p0 -b < ../libxml29_compat.patch && \
    ./configure --with-apxs2=/usr/bin/apxs --with-mysqli --enable-embedded-mysqli \
        --with-gd --with-mcrypt --enable-mbstring --with-pdo-mysql && \
    make -j"$(nproc)" && make install

# PHP 5 Apache module configuration
RUN printf '<FilesMatch ".+\\.ph(p[345]?|t|tml)$">\n\tSetHandler application/x-httpd-php\n</FilesMatch>\n<FilesMatch ".+\\.phps$">\n\tSetHandler application/x-httpd-php-source\n\tOrder Deny,Allow\n\tDeny from all\n</FilesMatch>\n<FilesMatch "^\\.ph(p[345]?|t|tml|ps)$">\n\tOrder Deny,Allow\n\tDeny from all\n</FilesMatch>\n<IfModule mod_userdir.c>\n\t<Directory /home/*/public_html>\n\t\tphp_admin_flag engine Off\n\t</Directory>\n</IfModule>\n' > /etc/apache2/mods-available/php5.conf && \
    printf 'LoadModule php5_module /usr/lib/apache2/modules/libphp5.so\n' > /etc/apache2/mods-available/php5.load && \
    cd /etc/apache2/mods-enabled && \
    a2enmod php5 && \
    a2dismod mpm_event && \
    a2enmod mpm_prefork

# ---------- Apache configuration ----------
RUN mkdir -p /var/www/cgi-bin /var/www/uploads && \
    chmod 0777 /var/www/uploads && \
    a2enmod cgi && a2enmod dav && a2enmod dav_fs && a2enmod dav_lock && a2enmod auth_digest && \
    chmod o+w /var/www/html && \
    rm -f /var/www/html/index.html

# ---------- MySQL setup ----------
RUN service mysql start && \
    mysql -u root -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('sploitme');" && \
    mysql -u root -psploitme -e "GRANT ALL ON *.* TO 'root'@'127.0.0.1' IDENTIFIED BY 'sploitme' WITH GRANT OPTION;" && \
    service mysql stop

# ---------- Drupal 7.5 (vulnerable to CVE-2014-3704 / Drupalgeddon) ----------
COPY shared/cookbooks/metasploitable/files/drupal/default_site.tar.gz /tmp/default_site.tar.gz
COPY shared/cookbooks/metasploitable/files/drupal/drupal.sql /tmp/drupal.sql

RUN mkdir -p /var/www/html/drupal && \
    cd /tmp && \
    wget -q https://ftp.drupal.org/files/projects/drupal-7.5.tar.gz && \
    tar xzf drupal-7.5.tar.gz --strip-components 1 -C /var/www/html/drupal && \
    wget -q https://ftp.drupal.org/files/projects/coder-7.x-2.5.tar.gz && \
    cd /var/www/html/drupal/sites && \
    tar xzf /tmp/default_site.tar.gz && \
    mkdir -p /var/www/html/drupal/sites/all/modules && \
    cd /var/www/html/drupal/sites/all/modules && \
    tar xzf /tmp/coder-7.x-2.5.tar.gz && \
    chown -R www-data:www-data /var/www/html/drupal

RUN service mysql start && \
    mysql -u root -psploitme -e "CREATE DATABASE drupal;" && \
    mysql -u root -psploitme -e "GRANT SELECT, INSERT, DELETE, CREATE, DROP, INDEX, ALTER ON drupal.* TO 'root'@'localhost' IDENTIFIED BY 'sploitme';" && \
    mysql -u root -psploitme drupal < /tmp/drupal.sql && \
    service mysql stop

# ---------- phpMyAdmin 3.5.8 ----------
COPY shared/cookbooks/metasploitable/files/phpmyadmin/config.inc.php /tmp/pma_config.inc.php

RUN cd /tmp && \
    wget -q https://files.phpmyadmin.net/phpMyAdmin/3.5.8/phpMyAdmin-3.5.8-all-languages.tar.gz && \
    tar xzf phpMyAdmin-3.5.8-all-languages.tar.gz -C /var/www/html && \
    mv /var/www/html/phpMyAdmin-3.5.8-all-languages /var/www/html/phpmyadmin && \
    cp /tmp/pma_config.inc.php /var/www/html/phpmyadmin/config.inc.php

# ---------- Entrypoint & verify ----------
COPY scenario-06/verify.sh /verify.sh
COPY scenario-06/entrypoint.sh /entrypoint.sh
RUN chmod +x /verify.sh /entrypoint.sh

EXPOSE 80
CMD ["/entrypoint.sh"]
