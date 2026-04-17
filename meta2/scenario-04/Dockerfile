FROM sysrepair/meta2-hardy:latest
# Install vsftpd
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd && \
    apt-get clean

# Create a regular FTP user for regression testing
RUN useradd -m -s /bin/bash ftpuser && \
    echo 'ftpuser:ftppass123' | chpasswd

# Configure vsftpd with anonymous login enabled (the vulnerability)
RUN echo "listen=YES" > /etc/vsftpd.conf && \
    echo "anonymous_enable=YES" >> /etc/vsftpd.conf && \
    echo "local_enable=YES" >> /etc/vsftpd.conf && \
    echo "write_enable=YES" >> /etc/vsftpd.conf && \
    echo "local_umask=022" >> /etc/vsftpd.conf && \
    echo "dirmessage_enable=YES" >> /etc/vsftpd.conf && \
    echo "xferlog_enable=YES" >> /etc/vsftpd.conf && \
    echo "connect_from_port_20=YES" >> /etc/vsftpd.conf && \
    echo "pam_service_name=vsftpd" >> /etc/vsftpd.conf

# Create anonymous FTP directory
RUN mkdir -p /home/ftp && \
    chown nobody:nogroup /home/ftp

# Expose FTP port
EXPOSE 21

# Start vsftpd in foreground
CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]
