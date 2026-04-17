FROM sysrepair/meta2-hardy:latest
# Install Apache, PHP5, and phpMyAdmin non-interactively
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apache2 \
        php5 \
        libapache2-mod-php5 \
        phpmyadmin \
        mysql-server && \
    apt-get clean

# Enable phpMyAdmin in Apache
RUN ln -s /etc/phpmyadmin/apache.conf /etc/apache2/conf.d/phpmyadmin.conf 2>/dev/null || true

# Create a sample PHP login form served over plain HTTP (no HTTPS)
RUN mkdir -p /var/www/login && \
    echo '<?php session_start(); ?>' > /var/www/login/index.php && \
    echo '<html><body>' >> /var/www/login/index.php && \
    echo '<h2>Login</h2>' >> /var/www/login/index.php && \
    echo '<form method="POST" action="index.php">' >> /var/www/login/index.php && \
    echo '  Username: <input type="text" name="username"><br>' >> /var/www/login/index.php && \
    echo '  Password: <input type="password" name="password"><br>' >> /var/www/login/index.php && \
    echo '  <input type="submit" value="Login">' >> /var/www/login/index.php && \
    echo '</form></body></html>' >> /var/www/login/index.php

# Apache serves everything over HTTP only — no SSL module, no certificates
# This means login credentials and phpMyAdmin sessions travel in cleartext

# Expose HTTP port only
EXPOSE 80

# Start Apache in foreground
CMD ["apache2ctl", "-D", "FOREGROUND"]
