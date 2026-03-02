FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

# Fix old repository URLs
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install vsftpd and openssl for certificate generation
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd openssl && \
    apt-get clean

# Create a regular FTP user
RUN useradd -m -s /bin/bash ftpuser && \
    echo 'ftpuser:ftppass123' | chpasswd

# Configure vsftpd WITHOUT SSL/TLS (the vulnerability)
# Credentials are transmitted in cleartext
RUN echo "listen=YES" > /etc/vsftpd.conf && \
    echo "anonymous_enable=NO" >> /etc/vsftpd.conf && \
    echo "local_enable=YES" >> /etc/vsftpd.conf && \
    echo "write_enable=YES" >> /etc/vsftpd.conf && \
    echo "local_umask=022" >> /etc/vsftpd.conf && \
    echo "dirmessage_enable=YES" >> /etc/vsftpd.conf && \
    echo "xferlog_enable=YES" >> /etc/vsftpd.conf && \
    echo "connect_from_port_20=YES" >> /etc/vsftpd.conf && \
    echo "pam_service_name=vsftpd" >> /etc/vsftpd.conf

# Note: ssl_enable is NOT set (defaults to NO), so all FTP traffic is unencrypted

# Expose FTP port
EXPOSE 21

# Start vsftpd in foreground
CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]
