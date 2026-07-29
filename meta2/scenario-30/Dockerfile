FROM sysrepair/meta2-hardy:latest
# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install telnet server and SSH as the secure alternative
RUN apt-get update && \
    apt-get install -y telnetd xinetd openssh-server

# Configure xinetd to enable telnet service
RUN echo "service telnet" > /etc/xinetd.d/telnet && \
    echo "{" >> /etc/xinetd.d/telnet && \
    echo "  disable = no" >> /etc/xinetd.d/telnet && \
    echo "  flags = REUSE" >> /etc/xinetd.d/telnet && \
    echo "  socket_type = stream" >> /etc/xinetd.d/telnet && \
    echo "  wait = no" >> /etc/xinetd.d/telnet && \
    echo "  user = root" >> /etc/xinetd.d/telnet && \
    echo "  server = /usr/sbin/in.telnetd" >> /etc/xinetd.d/telnet && \
    echo "  log_on_failure += USERID" >> /etc/xinetd.d/telnet && \
    echo "}" >> /etc/xinetd.d/telnet

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo "root:toor" | chpasswd

# Create start script: start xinetd (telnetd) and sshd (secure alternative) in
# the BACKGROUND, then keep PID 1 as `exec sleep infinity` so an agent that
# restarts xinetd/sshd can never kill the container. sshd daemonizes by default
# (no -D), and xinetd forks; both are live before the agent starts, so the
# "edited xinetd config but never reloaded" case stays detectable.
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/etc/init.d/xinetd start' >> /start.sh && \
    echo '/usr/sbin/sshd' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 22 23

# .preserve-cmd marker in the scenario dir makes the harness run this CMD instead
# of overriding it with `sleep infinity`.
CMD ["/start.sh"]
