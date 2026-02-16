FROM navig/ubuntu:8.04

# Fix old repository URLs
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install x11vnc and Xvfb (virtual framebuffer for headless VNC)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y x11vnc xvfb && \
    apt-get clean

# Create a VNC password file with the weak password "password"
RUN mkdir -p /root/.vnc && \
    x11vnc -storepasswd "password" /root/.vnc/passwd

# Create a startup script that launches Xvfb and x11vnc
RUN echo '#!/bin/bash' > /start-vnc.sh && \
    echo 'Xvfb :0 -screen 0 1024x768x16 &' >> /start-vnc.sh && \
    echo 'sleep 1' >> /start-vnc.sh && \
    echo 'x11vnc -display :0 -rfbauth /root/.vnc/passwd -forever -rfbport 5900 &' >> /start-vnc.sh && \
    echo 'wait' >> /start-vnc.sh && \
    chmod +x /start-vnc.sh

# Expose VNC port
EXPOSE 5900

# Start VNC server
CMD ["/start-vnc.sh"]
