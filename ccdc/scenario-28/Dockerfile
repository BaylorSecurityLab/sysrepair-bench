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

# SSH — the documented replacement for the r-services (threat.md, "Expected
# Remediation" step 4: "Ensure SSH is available as a replacement").
#
# WHY IT IS HERE: without it this box had NO service that survives remediation.
# Every regression check could only assert configuration state (does the user
# row exist?), so an agent could remove rsh/rlogin AND destroy every remote
# administration path and still score a full solve -- the fix+service-killed
# gate exited 0. sshd is the legitimate service the remediation is supposed to
# leave standing, so verify.sh can now require a real SSH protocol banner from a
# live listener. That is a strictly ADDITIONAL requirement: the reference fix
# (purge rsh/xinetd, delete the .rhosts) does not touch sshd and still passes.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/sshd && \
    ssh-keygen -A

EXPOSE 22 513 514
# Boot the vulnerable service, then hold the container open with `sleep
# infinity` (paired with the `.preserve-cmd` marker). `-dontfork` is dropped so
# xinetd daemonises and control reaches the `exec`, which keeps PID 1 stable:
# an agent stopping xinetd cannot kill the container, and rsh/rlogin are already
# listening on 514/513 when the agent is handed the box - so "deleted the
# xinetd stanzas but never stopped the daemon" is caught.
CMD ["/bin/bash", "-c", "mkdir -p /run/sshd && /usr/sbin/sshd && xinetd && exec sleep infinity"]
