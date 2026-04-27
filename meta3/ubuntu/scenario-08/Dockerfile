FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|mirrors.kernel.org|g; s|security.ubuntu.com|mirrors.kernel.org|g' /etc/apt/sources.list && \
    apt-get update && apt-get clean

# Install Samba from the old-releases repo (vulnerable version 2:4.1.6+dfsg-1ubuntu2)
# plus dependencies needed for verification
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
        samba \
        samba-common \
        samba-common-bin \
        smbclient \
        netcat \
        iproute \
    && apt-get clean

# Create a minimal smb.conf with a guest share so smbclient regression check works
RUN mkdir -p /srv/samba/public && chmod 0777 /srv/samba/public && \
    printf '%s\n' \
    '[global]' \
    '    workgroup = WORKGROUP' \
    '    server string = Meta3 Samba Server' \
    '    map to guest = Bad User' \
    '    log file = /var/log/samba/log.%m' \
    '    max log size = 50' \
    '    security = user' \
    '' \
    '[public]' \
    '    comment = Public Share' \
    '    path = /srv/samba/public' \
    '    browseable = yes' \
    '    read only = no' \
    '    guest ok = yes' \
    > /etc/samba/smb.conf

# Set Samba guest/nobody password and create test user
RUN useradd -M -s /usr/sbin/nologin smbguest 2>/dev/null || true && \
    (echo "smbguest" | smbpasswd -a -s smbguest 2>/dev/null || true)


EXPOSE 445

CMD ["smbd", "--foreground", "--no-process-group"]
