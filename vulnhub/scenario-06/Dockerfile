FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php && apt-get clean && rm -rf /var/lib/apt/lists/*
# PHP with NO open_basedir (VULNERABLE)
RUN echo "<?php echo file_get_contents(\$_GET['f']); ?>" > /var/www/html/read.php
EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]
