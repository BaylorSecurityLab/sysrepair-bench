FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install Java (for RMI registry)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y default-jdk openssh-server

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
