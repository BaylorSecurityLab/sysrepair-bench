FROM debian:11

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y apache2 openssl ssl-cert && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Generate self-signed certificate
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/apache-selfsigned.key \
    -out /etc/ssl/certs/apache-selfsigned.crt \
    -subj "/CN=localhost"

RUN a2enmod ssl

# Configure SSL with DEPRECATED protocols (VULNERABLE)
RUN printf '<VirtualHost *:443>\n\
    ServerName localhost\n\
    SSLEngine on\n\
    SSLCertificateFile /etc/ssl/certs/apache-selfsigned.crt\n\
    SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key\n\
    SSLProtocol all\n\
    SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW\n\
    DocumentRoot /var/www/html\n\
</VirtualHost>\n' > /etc/apache2/sites-available/default-ssl.conf

RUN a2ensite default-ssl

EXPOSE 80 443

COPY verify.sh /verify.sh
CMD ["apachectl", "-D", "FOREGROUND"]
