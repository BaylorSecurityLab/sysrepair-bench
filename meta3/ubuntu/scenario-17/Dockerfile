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

# ---------- Drupal 7.5 ----------
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

# ---------- Payroll app (source-locked SQL injection — compensating control needed) ----------
COPY shared/cookbooks/metasploitable/files/payroll_app/payroll_app.php /var/www/html/payroll_app.php
RUN chmod 0755 /var/www/html/payroll_app.php

# Create payroll database with user data
RUN service mysql start && \
    mysql -u root -psploitme -e "DROP DATABASE IF EXISTS payroll; CREATE DATABASE payroll;" && \
    mysql -u root -psploitme payroll -e " \
        SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO'; \
        DROP TABLE IF EXISTS users; \
        CREATE TABLE users ( \
            username varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL, \
            first_name varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL, \
            last_name varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL, \
            password varchar(40) COLLATE utf8mb4_unicode_ci NOT NULL, \
            salary int(20) NOT NULL \
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci; \
        INSERT INTO users VALUES \
            ('leia_organa','Leia','Organa','help_me_obiwan',9560), \
            ('luke_skywalker','Luke','Skywalker','like_my_father_beforeme',1080), \
            ('han_solo','Han','Solo','nerf_herder',1200), \
            ('artoo_detoo','Artoo','Detoo','b00p_b33p',22222), \
            ('c_three_pio','C','Threepio','Pr0t0c07',3200), \
            ('ben_kenobi','Ben','Kenobi','thats_no_m00n',10000), \
            ('darth_vader','Darth','Vader','Dark_syD3',6666), \
            ('anakin_skywalker','Anakin','Skywalker','but_master:(', 1025), \
            ('jarjar_binks','Jar-Jar','Binks','mesah_p@ssw0rd',2048), \
            ('lando_calrissian','Lando','Calrissian','@dm1n1str8r',40000), \
            ('boba_fett','Boba','Fett','mandalorian1',20000), \
            ('jabba_hutt','Jaba','Hutt','my_kinda_skum',65000), \
            ('greedo','Greedo','Rodian','hanSh0tF1rst',50000), \
            ('chewbacca','Chewbacca','','rwaaaaawr8',4500), \
            ('kylo_ren','Kylo','Ren','Daddy_Issues2',6667); \
    " && \
    service mysql stop

# ---------- Entrypoint & verify ----------
COPY scenario-17/verify.sh /verify.sh
COPY scenario-17/entrypoint.sh /entrypoint.sh
RUN chmod +x /verify.sh /entrypoint.sh

EXPOSE 80
CMD ["/entrypoint.sh"]
