FROM sysrepair/meta2-hardy:latest
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
