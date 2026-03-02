FROM ubuntu:25.10
# Scenario 27: Telnet server running (no SSH alternative)
# CWE-319: Cleartext Transmission of Sensitive Information
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y telnetd xinetd && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure telnet via xinetd
RUN cat > /etc/xinetd.d/telnet <<'EOF'
service telnet
{
    disable     = no
    flags       = REUSE
    socket_type = stream
    wait        = no
    user        = root
    server      = /usr/sbin/in.telnetd
    log_on_failure += USERID
}
EOF

# Create a user
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 23
CMD ["xinetd", "-dontfork"]
