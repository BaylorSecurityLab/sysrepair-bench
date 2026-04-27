FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y nginx php-fpm && apt-get clean && rm -rf /var/lib/apt/lists/*
# Configure nginx WITHOUT traversal protection (VULNERABLE)
RUN printf 'server {\n    listen 80;\n    root /var/www/html;\n    index index.php index.html;\n    location ~ \\.php$ {\n        include snippets/fastcgi-php.conf;\n        fastcgi_pass unix:/run/php/php7.3-fpm.sock;\n    }\n}' > /etc/nginx/sites-available/default
RUN echo "<?php phpinfo(); ?>" > /var/www/html/index.php
EXPOSE 80
CMD service php7.3-fpm start && nginx -g "daemon off;"
