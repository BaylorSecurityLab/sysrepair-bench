FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|mirrors.kernel.org|g; s|security.ubuntu.com|mirrors.kernel.org|g' /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl ca-certificates wget \
        gcc make build-essential \
        netcat && \
    apt-get clean

# ---------- ProFTPD 1.3.5 from source with mod_copy (CVE-2015-3306) ----------
RUN cd /tmp && \
    wget -q "https://github.com/proftpd/proftpd/archive/refs/tags/v1.3.5a.tar.gz" && \
    tar xzf v1.3.5a.tar.gz && \
    cd proftpd-1.3.5a && \
    ./configure --prefix=/opt/proftpd --with-modules=mod_copy && \
    make -j"$(nproc)" && make install

# ProFTPD init script
COPY shared/cookbooks/metasploitable/files/proftpd/proftpd /etc/init.d/proftpd
RUN chmod 760 /etc/init.d/proftpd && \
    sed -i -e 's/\r//g' /etc/init.d/proftpd

# Runtime directories
RUN mkdir -p /var/run/proftpd

# ---------- Entrypoint & verify ----------
COPY scenario-07/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21
CMD ["/entrypoint.sh"]
