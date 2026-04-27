FROM --platform=linux/amd64 ubuntu:14.04

# Fix repository URLs for EOL 14.04
RUN sed -i 's|archive.ubuntu.com|mirrors.kernel.org|g; s|security.ubuntu.com|mirrors.kernel.org|g' /etc/apt/sources.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl ca-certificates wget \
        gcc make build-essential \
        openssl libssl-dev \
        stunnel4 netcat iproute2 && \
    apt-get clean

# ---------- Create boba_fett user (UnrealIRCd runs as this user) ----------
RUN useradd -m -s /bin/bash boba_fett

# ---------- Download and extract UnrealIRCd 3.2.8.1 ----------
# Scenario tests network exposure (CWE-668), not the backdoor itself.
RUN mkdir -p /opt/unrealircd && \
    cd /tmp && \
    wget -q -O Unreal3.2.8.1.tar.gz \
        "https://web.archive.org/web/20160319114613/https://www.unrealircd.org/downloads/Unreal3.2.8.1.tar.gz" && \
    tar xzf Unreal3.2.8.1.tar.gz -C /opt/unrealircd

# ---------- UnrealIRCd configuration ----------
COPY shared/cookbooks/metasploitable/files/unrealircd/unrealircd.conf /opt/unrealircd/Unreal3.2/unrealircd.conf
COPY shared/cookbooks/metasploitable/files/unrealircd/ircd.motd /opt/unrealircd/Unreal3.2/ircd.motd

# ---------- Compile UnrealIRCd ----------
RUN cd /opt/unrealircd/Unreal3.2 && \
    ./configure \
        --with-showlistmodes --enable-hub --enable-prefixaq \
        --with-listen=5 \
        --with-dpath=/opt/unrealircd/Unreal3.2 \
        --with-spath=/opt/unrealircd/Unreal3.2/src/ircd \
        --with-nick-history=2000 --with-sendq=3000000 --with-bufferpool=18 \
        --with-hostname=metasploitableub --with-permissions=0600 \
        --with-fd-setsize=1024 --enable-dynamic-linking && \
    make

# Set ownership
RUN chown -R boba_fett /opt/unrealircd && \
    chmod 0400 /opt/unrealircd/Unreal3.2/unrealircd.conf && \
    chown boba_fett /opt/unrealircd/Unreal3.2/unrealircd.conf && \
    chmod 0400 /opt/unrealircd/Unreal3.2/ircd.motd && \
    chown boba_fett /opt/unrealircd/Unreal3.2/ircd.motd

# ---------- UnrealIRCd init script ----------
COPY shared/cookbooks/metasploitable/files/unrealircd/unrealircd /etc/init.d/unrealircd
RUN chmod 760 /etc/init.d/unrealircd && \
    sed -i -e 's/\r//g' /etc/init.d/unrealircd

# ---------- stunnel setup (for compensating control remediation path) ----------
RUN mkdir -p /etc/stunnel /var/run/stunnel4 && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/stunnel/stunnel.pem \
        -out /etc/stunnel/stunnel.pem \
        -subj "/CN=localhost" 2>/dev/null && \
    chmod 600 /etc/stunnel/stunnel.pem

# ---------- Entrypoint & verify ----------
COPY scenario-15/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose stunnel TLS port (post-remediation) and raw IRC (pre-remediation)
EXPOSE 6667 6697

CMD ["/entrypoint.sh"]
