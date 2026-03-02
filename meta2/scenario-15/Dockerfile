FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

# Fix old repository sources
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install distcc and gcc
RUN apt-get update && \
    apt-get install -y distcc gcc net-tools && \
    apt-get clean

# Create distcc user if it does not exist
RUN id distccd 2>/dev/null || useradd -r -s /bin/false distccd

# Create startup script that runs distccd WITHOUT --allow restriction
# This allows ANY host to connect and execute commands
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'distccd --daemon --no-detach --user distccd --port 3632 --log-stderr &' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 3632

CMD ["/start.sh"]
