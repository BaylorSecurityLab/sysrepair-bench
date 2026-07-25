FROM ubuntu:25.10
# Scenario 15: vsftpd anonymous upload enabled
# CWE-434: Unrestricted Upload of File with Dangerous Type
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd ftp && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure vsftpd with anonymous upload enabled
RUN mkdir -p /var/ftp/pub/upload && chmod 777 /var/ftp/pub/upload && \
    cat > /etc/vsftpd.conf <<'EOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
write_enable=YES
local_enable=YES
anon_root=/var/ftp
no_anon_password=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
EOF

RUN mkdir -p /var/run/vsftpd/empty

# Create a legitimate FTP user for functionality testing
RUN useradd -m -s /bin/bash ftpuser && echo 'ftpuser:ftppass123' | chpasswd


EXPOSE 21

# Boot the vulnerable service, then hold the container open with `sleep
# infinity`. Paired with the `.preserve-cmd` marker so the harness keeps this
# CMD instead of replacing it. `listen=YES` makes vsftpd run in the foreground,
# so it is backgrounded with `&` and control reaches the `exec`.
#   1. vsftpd must ALREADY BE RUNNING when the agent is handed the box, so a
#      config-only fix leaves the live daemon vulnerable and verify.sh fails.
#   2. PID 1 must NOT be vsftpd - restarting the service would otherwise kill
#      the container. `exec sleep infinity` keeps a stable PID 1.
CMD ["/bin/bash", "-c", "mkdir -p /var/run/vsftpd/empty; /usr/sbin/vsftpd /etc/vsftpd.conf </dev/null >/var/log/vsftpd-boot.log 2>&1 & sleep 1; exec sleep infinity"]
