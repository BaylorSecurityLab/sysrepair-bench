FROM ubuntu:rolling
# Scenario 18: Samba anonymous share access
# CWE-284: Improper Access Control
# Ubuntu 25.10 (Quantal)

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y samba smbclient && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Configure Samba with anonymous access
RUN cat > /etc/samba/smb.conf <<'EOF'
[global]
    workgroup = WORKGROUP
    server string = Vulnerable Samba Server
    security = user
    map to guest = Bad User
    guest account = nobody

[public]
    path = /srv/samba/public
    browseable = yes
    writable = yes
    guest ok = yes
    read only = no
    create mask = 0777
    directory mask = 0777

[private]
    path = /srv/samba/private
    browseable = yes
    writable = yes
    guest ok = yes
    read only = no
EOF

RUN mkdir -p /srv/samba/public /srv/samba/private && \
    echo "public data" > /srv/samba/public/readme.txt && \
    echo "CONFIDENTIAL: password=s3cret" > /srv/samba/private/secrets.txt && \
    chmod -R 777 /srv/samba/

# Create a legitimate Samba user
RUN useradd -m -s /bin/bash smbuser && \
    echo 'smbuser:smbpass123' | chpasswd && \
    (echo 'smbpass123'; echo 'smbpass123') | smbpasswd -a smbuser 2>/dev/null

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 139 445
CMD ["smbd", "--foreground", "--no-process-group"]
