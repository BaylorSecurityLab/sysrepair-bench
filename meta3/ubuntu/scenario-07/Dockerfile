FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|mirrors.kernel.org|g; s|security.ubuntu.com|mirrors.kernel.org|g' /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ca-certificates wget \
        gcc make build-essential \
        netcat && \
    apt-get clean

# ---------- ProFTPD 1.3.5 from source with mod_copy (CVE-2015-3306) ----------
# IMPORTANT: must be 1.3.5, NOT 1.3.5a. Release 1.3.5a is the FIX for
# CVE-2015-3306 (it makes SITE CPFR/CPTO require authentication); building
# 1.3.5a ships a NON-vulnerable server and the scenario becomes a no-op.
# The proftpd GitHub repo has no v1.3.5 tag (its earliest 1.3.5-line tag is the
# fixed v1.3.5a), so the vulnerable source is the Debian snapshot archive tarball.
# It is now VENDORED into the build context and its sha256 is pinned, so the build
# is hermetic and reproducible - no network fetch of the source, no dependence on
# the rate-limited single-host snapshot.debian.org archive. (meta3/ubuntu is the
# build-context root because of the shared/ sibling, so the file is COPYed as
# scenario-07/...). proftpd-dfsg_1.3.5.orig.tar.gz unpacks into proftpd-dfsg-1.3.5/.
COPY scenario-07/proftpd-dfsg_1.3.5.orig.tar.gz /tmp/proftpd-1.3.5.tar.gz
RUN echo "8ac3104658b9ce7cf308d9abc3d4b38168f0a7fdc25c1d88c565dedf319ba287  /tmp/proftpd-1.3.5.tar.gz" | sha256sum -c - && \
    cd /tmp && \
    tar xzf proftpd-1.3.5.tar.gz && \
    cd proftpd-dfsg-1.3.5 && \
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
