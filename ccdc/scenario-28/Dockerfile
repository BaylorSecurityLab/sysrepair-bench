FROM ubuntu:25.10
# Scenario 28: rsh/rlogin services enabled
# CWE-319: Cleartext Transmission of Sensitive Information
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y xinetd curl libwrap0 update-inetd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# rsh-server/rsh-client removed from Ubuntu 25.10 repos; install from jammy (22.04) archive
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        BASE_URL="http://archive.ubuntu.com/ubuntu/pool/universe/r/rsh-redone"; \
    else \
        BASE_URL="http://ports.ubuntu.com/ubuntu-ports/pool/universe/r/rsh-redone"; \
    fi && \
    curl -fsSL -o /tmp/rsh-server.deb "${BASE_URL}/rsh-redone-server_85-2build1_${ARCH}.deb" && \
    curl -fsSL -o /tmp/rsh-client.deb "${BASE_URL}/rsh-redone-client_85-2build1_${ARCH}.deb" && \
    dpkg -i /tmp/rsh-server.deb /tmp/rsh-client.deb || apt-get -f install -y && \
    rm -f /tmp/rsh-server.deb /tmp/rsh-client.deb

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
