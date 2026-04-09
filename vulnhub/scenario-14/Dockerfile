FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/www/html/wp-content/plugins/vulnerable-plugin && \
    echo "<?php /* Vulnerable plugin */ ?>" > /var/www/html/wp-content/plugins/vulnerable-plugin/index.php && \
    chmod -R 777 /var/www/html/wp-content/plugins
EXPOSE 80
COPY verify.sh /verify.sh
CMD ["apachectl", "-D", "FOREGROUND"]
