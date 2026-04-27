FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php php-mysql mariadb-server && apt-get clean && rm -rf /var/lib/apt/lists/*
# Simulate outdated Drupal 8
RUN mkdir -p /var/www/html/core/lib/Drupal
RUN printf '<?php\nnamespace Drupal;\nclass Drupal {\n  const VERSION = '"'"'8.5.0'"'"';\n}\n?>' > /var/www/html/core/lib/Drupal.php
RUN printf '8.5.0' > /var/www/html/core/VERSION.txt
EXPOSE 80
CMD service mariadb start && apachectl -D FOREGROUND
