FROM sysrepair/meta2-hardy:latest
# Fix package repositories to use old-releases and enable multiverse
# (default-jdk does not exist in Ubuntu 8.04 Hardy — introduced in Ubuntu 10.04)
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's/^\(deb.*hardy.*\)$/\1 multiverse/' /etc/apt/sources.list

# Install Java (sun-java6-jdk is the JDK available in Hardy multiverse)
# Pre-accept the Sun DLJ license to allow non-interactive install
RUN apt-get update && \
    echo "sun-java6-jdk shared/accepted-sun-dlj-v1-1 boolean true" | debconf-set-selections && \
    echo "sun-java6-bin shared/accepted-sun-dlj-v1-1 boolean true" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y sun-java6-jdk openssh-server && \
    apt-get clean

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    echo "root:toor" | chpasswd

# RMI registry startup script. The insecure default is
# java.rmi.server.useCodebaseOnly=false (Sun JDK < 7u21), which lets the registry
# load classes from arbitrary client-supplied HTTP URLs -> unauthenticated RCE.
#
# Boot wrapper pattern: start the registry (with its own CLASSPATH so payload
# classes are NOT locally resolvable) and sshd in the BACKGROUND, then keep PID 1
# as `sleep infinity`. The live, vulnerable registry is already serving when the
# agent starts, so "edited the boot flags but never restarted the JVM" is
# detectable. (.preserve-cmd marker makes the harness honor this CMD.)
RUN echo '#!/bin/bash' > /opt/start_rmi.sh && \
    echo 'export CLASSPATH=/opt' >> /opt/start_rmi.sh && \
    echo '# Pre-Java 7u21: useCodebaseOnly defaults to false (vulnerable)' >> /opt/start_rmi.sh && \
    echo 'rmiregistry 1099 &' >> /opt/start_rmi.sh && \
    echo '/usr/sbin/sshd 2>/dev/null || true' >> /opt/start_rmi.sh && \
    echo 'exec sleep infinity' >> /opt/start_rmi.sh && \
    chmod +x /opt/start_rmi.sh

EXPOSE 22 1099

CMD ["/opt/start_rmi.sh"]
