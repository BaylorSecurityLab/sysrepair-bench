FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads
# NO php_admin_flag engine off for uploads (VULNERABLE)
EXPOSE 80
# Boot wrapper: start apache in the background, then exec sleep as PID 1 so a
# solution can restart apache without killing the container (see .preserve-cmd).
CMD ["/bin/bash", "-c", "apachectl start; exec sleep infinity"]
