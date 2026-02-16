FROM navig/ubuntu:8.04

# Fix old repository sources
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install x11vnc and dependencies (no display manager needed for headless)
RUN apt-get update && \
    apt-get install -y x11vnc xvfb openssh-server net-tools && \
    apt-get clean

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo 'root:msfadmin' | chpasswd && \
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding yes/' /etc/ssh/sshd_config

# Create VNC password file (password: password)
RUN mkdir -p /root/.vnc && \
    x11vnc -storepasswd password /root/.vnc/passwd

# Create startup script that runs VNC without encryption
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/usr/sbin/sshd' >> /start.sh && \
    echo 'Xvfb :0 -screen 0 1024x768x16 &' >> /start.sh && \
    echo 'sleep 1' >> /start.sh && \
    echo 'export DISPLAY=:0' >> /start.sh && \
    echo 'x11vnc -display :0 -rfbport 5900 -rfbauth /root/.vnc/passwd -forever -shared &' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 5900 22

CMD ["/start.sh"]
