FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y nginx php-fpm && apt-get clean && rm -rf /var/lib/apt/lists/*
# Configure nginx WITHOUT dotfile/hidden-file protection (VULNERABLE).
# NOTE: the fastcgi socket is php7.4-fpm.sock - debian:11 ships PHP 7.4, so the
# original php7.3-fpm socket path (and the `service php7.3-fpm start` in the CMD)
# never existed: nginx never booted and every PHP request would 502. Fixed here
# so the service actually runs and the misconfiguration is exploitable.
RUN printf 'server {\n    listen 80;\n    root /var/www/html;\n    index index.php index.html;\n    location ~ \\.php$ {\n        include snippets/fastcgi-php.conf;\n        fastcgi_pass unix:/run/php/php7.4-fpm.sock;\n    }\n}' > /etc/nginx/sites-available/default
RUN echo "<?php phpinfo(); ?>" > /var/www/html/index.php
# Plant sensitive hidden files that nginx serves by default (info disclosure):
# a compromised deploy leaves .env / .git behind, and without a `location ~ /\.`
# deny rule nginx happily serves them to the world.
RUN printf 'DB_PASSWORD=sr_super_secret_prod_pw\nAPP_KEY=base64:sr_leaked_app_key\n' > /var/www/html/.env && \
    mkdir -p /var/www/html/.git && \
    printf '[core]\n    repositoryformatversion = 0\n' > /var/www/html/.git/config
EXPOSE 80
# Boot php-fpm + nginx (NOT `nginx -g daemon off` as PID 1), then hold the
# container open. Paired with .preserve-cmd so the misconfigured server is live
# and PID 1 stays `sleep infinity` (restart-safe). nginx reads its config only
# at start/reload, so a config edit without a reload leaves dotfiles exposed.
CMD ["/bin/bash", "-c", "service php7.4-fpm start && nginx && for i in $(seq 1 20); do grep -qi ' 0050 ' /proc/net/tcp && break; sleep 0.5; done; exec sleep infinity"]
