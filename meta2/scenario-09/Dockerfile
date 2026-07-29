FROM sysrepair/meta2-hardy:latest
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

# Create startup script that runs VNC without encryption, bound to ALL
# interfaces (0.0.0.0) so cleartext RFB traffic is exposed on the network. The
# daemons run in the BACKGROUND and PID 1 is `exec sleep infinity` so an agent
# restarting x11vnc can never kill the container. The interface x11vnc binds is
# fixed at startup, which makes the "reconfigured but never restarted" case
# detectable by the behavioural verifier.
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/usr/sbin/sshd' >> /start.sh && \
    echo 'Xvfb :0 -screen 0 1024x768x16 &' >> /start.sh && \
    echo 'sleep 1' >> /start.sh && \
    echo 'export DISPLAY=:0' >> /start.sh && \
    echo 'x11vnc -display :0 -rfbport 5900 -rfbauth /root/.vnc/passwd -forever -shared &' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 5900 22

# .preserve-cmd makes the harness run this CMD (start the real daemons) instead
# of overriding it with `sleep infinity`.
CMD ["/start.sh"]
