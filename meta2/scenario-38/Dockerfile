FROM sysrepair/meta2-hardy:latest
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y samba smbclient && \
    apt-get clean

# Introduce the vulnerable directive plus a world-reachable share. The compensating
# control must (a) remove/disable `username map script`, (b) scope the share to a
# trusted CIDR via `hosts allow`, while the share stays readable from the trusted
# network (simulated by loopback in verify.sh).
RUN mkdir -p /srv/share && echo 'SHARE_OK' > /srv/share/hello.txt && chmod -R 0755 /srv/share

RUN printf '%s\n' \
    '[global]' \
    '   workgroup = WORKGROUP' \
    '   server string = meta2-legacy' \
    '   security = user' \
    '   passdb backend = tdbsam' \
    '   username map script = /bin/echo' \
    '   log file = /var/log/samba/log.%m' \
    '   max log size = 50' \
    '' \
    '[legacy]' \
    '   path = /srv/share' \
    '   browsable = yes' \
    '   read only = yes' \
    '   guest ok = yes' \
    > /etc/samba/smb.conf

RUN echo '#!/bin/bash' > /start.sh && \
    echo '/etc/init.d/samba start 2>/dev/null || (smbd -D; nmbd -D)' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 139 445
CMD ["/start.sh"]
