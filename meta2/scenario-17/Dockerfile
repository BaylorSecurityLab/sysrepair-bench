FROM navig/ubuntu:8.04

# Fix old repository URLs
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y netcat inetutils-inetd && \
    apt-get clean

# Create a fake UnrealIRCd 3.2.8.1 service that responds to IRC connections
# This simulates the backdoored version that OpenVAS detects by version string
RUN mkdir -p /opt/unrealircd

# Create a simulated IRC server script that identifies as UnrealIRCd 3.2.8.1
RUN echo '#!/bin/bash' > /opt/unrealircd/ircd-sim.sh && \
    echo '# Simulated backdoored UnrealIRCd 3.2.8.1' >> /opt/unrealircd/ircd-sim.sh && \
    echo 'while true; do' >> /opt/unrealircd/ircd-sim.sh && \
    echo '  nc -l -p 6667 -e /opt/unrealircd/irc-handler.sh 2>/dev/null' >> /opt/unrealircd/ircd-sim.sh && \
    echo '  sleep 1' >> /opt/unrealircd/ircd-sim.sh && \
    echo 'done' >> /opt/unrealircd/ircd-sim.sh && \
    chmod +x /opt/unrealircd/ircd-sim.sh

# IRC handler that returns the vulnerable version banner and processes AB; backdoor
RUN echo '#!/bin/bash' > /opt/unrealircd/irc-handler.sh && \
    echo 'echo ":irc.local NOTICE Auth :*** Looking up your hostname..."' >> /opt/unrealircd/irc-handler.sh && \
    echo 'echo ":irc.local NOTICE Auth :*** Found your hostname"' >> /opt/unrealircd/irc-handler.sh && \
    echo 'read LINE' >> /opt/unrealircd/irc-handler.sh && \
    echo 'if echo "$LINE" | grep -q "^AB;"; then' >> /opt/unrealircd/irc-handler.sh && \
    echo '  CMD=$(echo "$LINE" | sed "s/^AB;//")' >> /opt/unrealircd/irc-handler.sh && \
    echo '  eval "$CMD" 2>&1' >> /opt/unrealircd/irc-handler.sh && \
    echo 'else' >> /opt/unrealircd/irc-handler.sh && \
    echo '  echo ":irc.local 002 user :Your host is irc.local, running version Unreal3.2.8.1"' >> /opt/unrealircd/irc-handler.sh && \
    echo '  echo ":irc.local 003 user :This server was created on 2009/11/01"' >> /opt/unrealircd/irc-handler.sh && \
    echo '  echo ":irc.local 004 user irc.local Unreal3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGjZ"' >> /opt/unrealircd/irc-handler.sh && \
    echo 'fi' >> /opt/unrealircd/irc-handler.sh && \
    chmod +x /opt/unrealircd/irc-handler.sh

# Store the version for easy checking
RUN echo "3.2.8.1" > /opt/unrealircd/VERSION

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/opt/unrealircd/ircd-sim.sh &' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 6667

CMD ["/start.sh"]
