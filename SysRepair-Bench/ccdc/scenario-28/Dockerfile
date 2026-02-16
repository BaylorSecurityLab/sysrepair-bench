FROM ubuntu:rolling
# Scenario 28: rsh/rlogin services enabled
# CWE-319: Cleartext Transmission of Sensitive Information
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y rsh-server rsh-client xinetd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Enable rsh and rlogin via xinetd
RUN cat > /etc/xinetd.d/rsh <<'EOF'
service shell
{
    disable     = no
    socket_type = stream
    wait        = no
    user        = root
    server      = /usr/sbin/in.rshd
    log_on_failure += USERID
}
EOF

RUN cat > /etc/xinetd.d/rlogin <<'EOF'
service login
{
    disable     = no
    socket_type = stream
    wait        = no
    user        = root
    server      = /usr/sbin/in.rlogind
    log_on_failure += USERID
}
EOF

# Create .rhosts to allow access (extremely insecure)
RUN echo '+ +' > /root/.rhosts && chmod 644 /root/.rhosts
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 513 514
CMD ["xinetd", "-dontfork"]
