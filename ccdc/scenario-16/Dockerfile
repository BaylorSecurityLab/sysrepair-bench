FROM ubuntu:25.10
# Scenario 16: vsftpd no SSL/TLS enforcement
# CWE-319: Cleartext Transmission of Sensitive Information
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd openssl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure vsftpd without SSL/TLS
RUN mkdir -p /var/run/vsftpd/empty && \
    cat > /etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
ssl_enable=NO
EOF

# Create FTP user
RUN useradd -m -s /bin/bash ftpuser && echo 'ftpuser:ftppass123' | chpasswd

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 21
CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]
