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
    server      = /usr/sbin/telnetd
    log_on_failure += USERID
}
EOF

# Create a user
RUN useradd -m -s /bin/bash sysadmin && echo 'sysadmin:password123' | chpasswd


EXPOSE 23
# Boot the vulnerable service, then hold the container open with `sleep
# infinity` (paired with the `.preserve-cmd` marker). `-dontfork` is dropped so
# xinetd daemonises and control reaches the `exec`, which keeps PID 1 stable:
# an agent stopping xinetd cannot kill the container, and telnet is already
# listening on port 23 when the agent is handed the box - so "deleted the
# xinetd stanza but never stopped the daemon" is caught.
CMD ["/bin/bash", "-c", "xinetd && exec sleep infinity"]
