FROM ubuntu:25.10
# Scenario 19: PHP dangerous functions enabled
# CWE-78: OS Command Injection
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y php-fpm php-cli nginx curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Ensure dangerous PHP functions are NOT disabled (vulnerable state)
RUN PHP_INI=$(php -r "echo php_ini_loaded_file();" 2>/dev/null) && \
    if [ -n "$PHP_INI" ]; then \
    sed -i 's/^disable_functions.*/disable_functions =/' "$PHP_INI"; \
    fi && \
    for ini in /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini; do \
    [ -f "$ini" ] && sed -i 's/^disable_functions.*/disable_functions =/' "$ini"; \
    done

# Also enable allow_url_fopen and allow_url_include
RUN for ini in /etc/php/*/fpm/php.ini /etc/php/*/cli/php.ini; do \
    [ -f "$ini" ] && \
    sed -i 's/^allow_url_fopen.*/allow_url_fopen = On/' "$ini" && \
    sed -i 's/^;allow_url_include.*/allow_url_include = On/' "$ini" && \
    sed -i 's/^allow_url_include.*/allow_url_include = On/' "$ini" && \
    sed -i 's/^expose_php.*/expose_php = On/' "$ini"; \
    done

# Set up Nginx with PHP-FPM
# SCENARIO-DESIGN FIX: the vhost used to hardcode unix:/run/php/php-fpm.sock,
# but Ubuntu's fpm pool listens on /run/php/phpX.Y-fpm.sock. Every PHP request
# 502'd, so the expose_php=On vulnerability was NOT observable in the built
# image and verify.sh's X-Powered-By check passed on the vulnerable baseline.
# Derive the real socket path from the shipped pool config at build time.
RUN SOCK=$(grep -hE '^[[:space:]]*listen[[:space:]]*=' /etc/php/*/fpm/pool.d/www.conf | head -1 | cut -d= -f2 | tr -d ' ') && \
    printf 'server { listen 80; root /var/www/html; index index.php index.html; location ~ \\.php$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:%s; } }\n' "$SOCK" > /etc/nginx/sites-enabled/default

# Create a test PHP file
RUN echo '<?php echo "PHP is working: " . phpversion(); ?>' > /var/www/html/index.php


EXPOSE 80
# Boot BOTH vulnerable services (php-fpm and nginx), then hold the container
# open with `sleep infinity` (paired with the `.preserve-cmd` marker).
# `-g 'daemon off;'` is dropped so nginx daemonises and control reaches the
# `exec`, which keeps PID 1 stable: an agent restarting php-fpm or nginx cannot
# kill the container, and the web tier is already serving PHP with
# expose_php=On / disable_functions= when the agent is handed the box.
CMD ["bash", "-c", "mkdir -p /run/php && service $(ls /etc/init.d/ | grep php.*fpm | head -1) start && nginx && exec sleep infinity"]
