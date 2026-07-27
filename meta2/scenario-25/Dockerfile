FROM sysrepair/meta2-hardy:latest
# Install Apache, PHP5, and phpMyAdmin non-interactively.
# curl + openssl are needed by the behavioural verifier so it can drive a REAL
# HTTP request against the login form and a REAL TLS handshake against 443
# (proving the transport is actually encrypted, not just configured to be).
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        apache2 \
        php5 \
        libapache2-mod-php5 \
        phpmyadmin \
        mysql-server \
        curl \
        openssl && \
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

# Apache serves everything over HTTP only — no SSL module, no certificates.
# Login credentials and phpMyAdmin sessions therefore travel in cleartext.

# Expose HTTP port only
EXPOSE 80

# .preserve-cmd: boot Apache in the BACKGROUND so a real, vulnerable daemon is
# already serving the cleartext login form on port 80 when the agent starts
# (this makes the "edited the vhost but never restarted Apache" case
# detectable — Apache only adopts a2enmod / a2ensite / RewriteRule changes at
# start-up), then keep PID 1 as `sleep infinity` so an agent restarting Apache
# can never kill the container.
CMD ["/bin/bash", "-c", ". /etc/apache2/envvars 2>/dev/null; apache2ctl start >/dev/null 2>&1; exec sleep infinity"]
