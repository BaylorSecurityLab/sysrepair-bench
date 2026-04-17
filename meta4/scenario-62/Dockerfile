FROM --platform=linux/amd64 debian:buster-slim

# Dovecot 2.3.7 contains a pre-authentication buffer overflow (CVE-2019-11500)
# via malformed quoted strings in the IMAP/ManageSieve protocols.
# This version cannot be patched by upgrade; compensating controls are required.
#
# NOTE: Run with --cap-add=NET_ADMIN to allow iptables rules in verify.sh.

# Redirect buster (EOL) repos to archive
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g; /buster-updates/d' /etc/apt/sources.list

RUN apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --no-install-recommends dovecot-core dovecot-imapd \
        iptables iproute2 curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 143 993

CMD ["dovecot", "-F"]
