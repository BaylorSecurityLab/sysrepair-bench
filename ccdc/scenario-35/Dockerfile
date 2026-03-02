FROM ubuntu:25.10
# Targets Ubuntu 25.10

ENV DEBIAN_FRONTEND=noninteractive

# Install NFS server with insecure exports
RUN apt-get update && apt-get install -y \
    nfs-kernel-server \
    nfs-common \
    systemctl \
    coreutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create the NFS share directory
RUN mkdir -p /srv/nfs && chmod 777 /srv/nfs
RUN echo "NFS test data - sensitive information" > /srv/nfs/data.txt

# Configure insecure NFS exports:
# - Exported to everyone (*)
# - rw: read-write access
# - no_root_squash: remote root has full root privileges (DANGEROUS)
# - sync: synchronous writes
RUN echo "/srv/nfs *(rw,sync,no_root_squash,no_subtree_check)" > /etc/exports

# Enable the NFS server
RUN systemctl enable nfs-kernel-server 2>/dev/null || true

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["sleep", "infinity"]
