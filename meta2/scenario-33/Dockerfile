FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

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

# Create a simple RMI registry startup script
# The insecure default is java.rmi.server.useCodebaseOnly=false (pre-Java 7u21)
# which allows remote class loading from arbitrary HTTP URLs
RUN echo '#!/bin/bash' > /opt/start_rmi.sh && \
    echo 'export CLASSPATH=/opt' >> /opt/start_rmi.sh && \
    echo '# Start RMI registry on port 1099 with insecure defaults' >> /opt/start_rmi.sh && \
    echo '# Pre-Java 7u21: useCodebaseOnly defaults to false (vulnerable)' >> /opt/start_rmi.sh && \
    echo 'rmiregistry 1099 &' >> /opt/start_rmi.sh && \
    echo 'echo "RMI Registry started on port 1099"' >> /opt/start_rmi.sh && \
    echo '/usr/sbin/sshd -D' >> /opt/start_rmi.sh && \
    chmod +x /opt/start_rmi.sh

EXPOSE 22 1099

CMD ["/opt/start_rmi.sh"]
