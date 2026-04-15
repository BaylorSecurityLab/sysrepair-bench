FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs to old-releases.ubuntu.com
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install CUPS printing server and SSL libraries
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        cups \
        cups-client \
        libcups2 \
        openssl && \
    apt-get clean

# Allow CUPS to listen on all interfaces (not just localhost)
RUN sed -i 's|^Listen localhost:631|Listen *:631|' /etc/cups/cupsd.conf

# Allow access from any host for the admin interface
RUN sed -i '/<\/Location>/i\\    Allow All' /etc/cups/cupsd.conf 2>/dev/null || true

# Inject deprecated TLS version allowance — vulnerable configuration
RUN echo '' >> /etc/cups/cupsd.conf && \
    echo '# Vulnerable: permits deprecated SSLv3, TLSv1.0, and TLSv1.1 connections' >> /etc/cups/cupsd.conf && \
    echo 'SSLOptions AllowSSL3 AllowTLS1 AllowTLS11' >> /etc/cups/cupsd.conf

# Generate a self-signed certificate for CUPS HTTPS
RUN mkdir -p /etc/cups/ssl && \
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout /etc/cups/ssl/server.key \
        -out /etc/cups/ssl/server.crt \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=localhost" && \
    chmod 600 /etc/cups/ssl/server.key

EXPOSE 631

CMD ["/usr/sbin/cupsd", "-f"]
