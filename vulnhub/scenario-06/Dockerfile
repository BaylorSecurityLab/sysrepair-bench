FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php && apt-get clean && rm -rf /var/lib/apt/lists/*
# PHP with NO open_basedir (VULNERABLE)
RUN echo "<?php echo file_get_contents(\$_GET['f']); ?>" > /var/www/html/read.php
EXPOSE 80
# Boot the vulnerable apache+php (no open_basedir) then hold the container open.
# Paired with .preserve-cmd: httpd must already be serving read.php so a
# php.ini edit that never restarts apache still fails verify.sh; PID 1 stays
# `sleep infinity` so restarting apache cannot kill the container.
CMD ["/bin/bash", "-c", "apachectl start && exec sleep infinity"]
