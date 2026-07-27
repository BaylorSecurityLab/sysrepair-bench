FROM sysrepair/meta2-hardy:latest
# Install Samba (Ubuntu 8.04 ships Samba 3.0.28a which is vulnerable)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y samba smbclient && \
    apt-get clean

# Create a test user and shared directory
RUN useradd -m -s /bin/bash smbuser && \
    echo "smbuser:smbuser" | chpasswd && \
    (echo "smbuser"; echo "smbuser") | smbpasswd -a -s smbuser

RUN mkdir -p /srv/samba/shared && \
    chmod 0777 /srv/samba/shared && \
    echo "This is a test file in the Samba share." > /srv/samba/shared/testfile.txt

# Configure Samba with the vulnerable 'username map script' option.
# CVE-2007-2447: a username map script re-expands the client-supplied username
# through /bin/sh, so shell metacharacters in the username run as the smbd user.
# Hardy ships Samba 3.0.28a, which sanitises %U before invoking the map script
# (the base CVE is patched), so we reproduce the exploitable end-to-end behaviour
# with an admin-supplied map script that unsafely `eval`s its argument -- exactly
# the real-world misconfiguration the CVE describes.
RUN printf '%s\n' \
    '#!/bin/sh' \
    '# Unsafe username map script: re-expands the client username through the' \
    '# shell (CVE-2007-2447 pattern). A metacharacter username executes here.' \
    'eval "/bin/echo $1"' \
    > /usr/local/bin/smb_usermap.sh && \
    chmod +x /usr/local/bin/smb_usermap.sh

RUN cp /etc/samba/smb.conf /etc/samba/smb.conf.bak

RUN echo '[global]' > /etc/samba/smb.conf && \
    echo '   workgroup = WORKGROUP' >> /etc/samba/smb.conf && \
    echo '   server string = Samba Server' >> /etc/samba/smb.conf && \
    echo '   security = user' >> /etc/samba/smb.conf && \
    echo '   map to guest = bad user' >> /etc/samba/smb.conf && \
    echo '   username map script = /usr/local/bin/smb_usermap.sh' >> /etc/samba/smb.conf && \
    echo '   log file = /var/log/samba/log.%m' >> /etc/samba/smb.conf && \
    echo '   max log size = 1000' >> /etc/samba/smb.conf && \
    echo '' >> /etc/samba/smb.conf && \
    echo '[shared]' >> /etc/samba/smb.conf && \
    echo '   path = /srv/samba/shared' >> /etc/samba/smb.conf && \
    echo '   browseable = yes' >> /etc/samba/smb.conf && \
    echo '   read only = no' >> /etc/samba/smb.conf && \
    echo '   guest ok = yes' >> /etc/samba/smb.conf && \
    echo '   create mask = 0644' >> /etc/samba/smb.conf && \
    echo '   directory mask = 0755' >> /etc/samba/smb.conf

# Boot wrapper: nmbd/smbd daemonize into the BACKGROUND (-D), then PID 1 stays
# `sleep infinity` (via exec) so an agent restarting Samba can never kill the
# container. A .preserve-cmd marker makes the harness run this CMD, so the
# username-map injection is live against a running smbd before the agent starts.
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/usr/sbin/nmbd -D' >> /start.sh && \
    echo '/usr/sbin/smbd -D' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 139 445

CMD ["/start.sh"]
