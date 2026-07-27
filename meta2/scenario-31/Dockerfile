FROM sysrepair/meta2-hardy:latest
# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install rlogin server (rsh-server) and SSH as secure alternative
RUN apt-get update && \
    apt-get install -y rsh-server xinetd openssh-server

# rsh-server ships the in.rlogind/in.rshd/in.rexecd binaries but installs NO
# xinetd service files (it relies on update-inetd, which is a no-op with only
# xinetd present). Explicitly enable rlogin (port 513/login) under xinetd so the
# cleartext service actually listens.
RUN echo "service login" > /etc/xinetd.d/rlogin && \
    echo "{" >> /etc/xinetd.d/rlogin && \
    echo "  disable = no" >> /etc/xinetd.d/rlogin && \
    echo "  socket_type = stream" >> /etc/xinetd.d/rlogin && \
    echo "  protocol = tcp" >> /etc/xinetd.d/rlogin && \
    echo "  wait = no" >> /etc/xinetd.d/rlogin && \
    echo "  user = root" >> /etc/xinetd.d/rlogin && \
    echo "  server = /usr/sbin/in.rlogind" >> /etc/xinetd.d/rlogin && \
    echo "  server_args = -l -h" >> /etc/xinetd.d/rlogin && \
    echo "  log_on_failure += USERID" >> /etc/xinetd.d/rlogin && \
    echo "}" >> /etc/xinetd.d/rlogin

# Configure passwordless rlogin via /etc/hosts.equiv
# WARNING: This is extremely insecure - allows any host/user
RUN echo "+ +" > /etc/hosts.equiv && \
    chmod 644 /etc/hosts.equiv

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo "root:toor" | chpasswd

# Create start script: start xinetd (rlogind) and sshd (secure alternative) in
# the BACKGROUND, then keep PID 1 as `exec sleep infinity` so an agent that
# restarts xinetd/sshd can never kill the container. sshd daemonizes by default
# (no -D); both are live before the agent starts, so the "edited xinetd config
# but never reloaded" case stays detectable.
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/etc/init.d/xinetd start' >> /start.sh && \
    echo '/usr/sbin/sshd' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 22 513

# .preserve-cmd marker in the scenario dir makes the harness run this CMD instead
# of overriding it with `sleep infinity`.
CMD ["/start.sh"]
