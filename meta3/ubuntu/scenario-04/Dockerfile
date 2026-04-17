FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs to mirrors.kernel.org
RUN sed -i 's|archive.ubuntu.com|mirrors.kernel.org|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|mirrors.kernel.org|g' /etc/apt/sources.list

# Install CUPS printing server, SSL libraries, and nmap for verification
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        cups \
        cups-client \
        libcups2 \
        openssl \
        nmap && \
    apt-get clean

# Allow CUPS to listen on all interfaces
RUN sed -i 's|^Listen localhost:631|Listen *:631|' /etc/cups/cupsd.conf

# Allow access from any host
RUN sed -i '/<\/Location>/i\\    Allow All' /etc/cups/cupsd.conf 2>/dev/null || true

# Inject weak cipher suites and enable RC4/DH — vulnerable configuration
RUN echo '' >> /etc/cups/cupsd.conf && \
    echo '# Vulnerable: permits RC4, 3DES (SWEET32), and anonymous DH cipher suites' >> /etc/cups/cupsd.conf && \
    echo 'SSLOptions AllowRC4 AllowDH' >> /etc/cups/cupsd.conf

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
