FROM navig/ubuntu:8.04

# Fix old repository URLs
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

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

# Configure Samba with the vulnerable 'username map script' option
# CVE-2007-2447: shell metacharacters in username are passed to /bin/sh via this directive
RUN cp /etc/samba/smb.conf /etc/samba/smb.conf.bak

RUN echo '[global]' > /etc/samba/smb.conf && \
    echo '   workgroup = WORKGROUP' >> /etc/samba/smb.conf && \
    echo '   server string = Samba Server' >> /etc/samba/smb.conf && \
    echo '   security = user' >> /etc/samba/smb.conf && \
    echo '   map to guest = bad user' >> /etc/samba/smb.conf && \
    echo '   username map script = /bin/echo' >> /etc/samba/smb.conf && \
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

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/usr/sbin/nmbd -D' >> /start.sh && \
    echo '/usr/sbin/smbd -D' >> /start.sh && \
    echo 'sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 139 445

CMD ["/start.sh"]
