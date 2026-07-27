FROM sysrepair/meta2-hardy:latest
# Install x11vnc and Xvfb (virtual framebuffer for headless VNC). openssl is
# used by the behavioural verifier to compute the VNC (DES) auth response.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y x11vnc xvfb openssl && \
    apt-get clean

# Keep a passwd file around for documentation of the weak default.
RUN mkdir -p /root/.vnc && \
    x11vnc -storepasswd "password" /root/.vnc/passwd

# Create a startup script that launches Xvfb and x11vnc in the BACKGROUND, then
# keeps PID 1 as `sleep infinity` so an agent restarting x11vnc can never kill
# the container.
#
# The weak VNC password "password" is supplied at startup via -passwd, so the
# LIVE daemon holds it in its process arguments. Changing the password therefore
# requires actually restarting x11vnc — which is exactly what makes the
# "reconfigured but never restarted" case detectable by the behavioural verifier.
RUN echo '#!/bin/bash' > /start-vnc.sh && \
    echo 'Xvfb :0 -screen 0 1024x768x16 &' >> /start-vnc.sh && \
    echo 'sleep 1' >> /start-vnc.sh && \
    echo 'x11vnc -display :0 -passwd password -forever -rfbport 5900 &' >> /start-vnc.sh && \
    echo 'exec sleep infinity' >> /start-vnc.sh && \
    chmod +x /start-vnc.sh

# Expose VNC port
EXPOSE 5900

# .preserve-cmd makes the harness run this CMD (start the real VNC daemon)
# instead of overriding it with `sleep infinity`.
CMD ["/start-vnc.sh"]
