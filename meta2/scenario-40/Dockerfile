FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        openssh-server \
        vnc4server \
        xauth \
        x11-xkb-utils \
        netcat && \
    apt-get clean

RUN mkdir -p /var/run/sshd /root/.vnc && \
    echo 'root:toor' | chpasswd && \
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    printf 'password\npassword\nn\n' | vncpasswd /root/.vnc/passwd && \
    chmod 600 /root/.vnc/passwd

# Vulnerable start: VNC bound to all interfaces on :5900 (no SSH tunnel required).
# Compensating control: bind to 127.0.0.1 so access is only possible after SSH-tunneling.
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/usr/sbin/sshd' >> /start.sh && \
    echo 'if [ -f /root/.vnc/bound-local ]; then' >> /start.sh && \
    echo '  vncserver :0 -interface 127.0.0.1 -geometry 1024x768 > /dev/null 2>&1 || \\' >> /start.sh && \
    echo '    (while true; do nc -l -p 5900 -s 127.0.0.1 > /dev/null 2>&1; done &)' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '  vncserver :0 -geometry 1024x768 > /dev/null 2>&1 || \\' >> /start.sh && \
    echo '    (while true; do nc -l -p 5900 > /dev/null 2>&1; done &)' >> /start.sh && \
    echo 'fi' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 22 5900
CMD ["/start.sh"]
