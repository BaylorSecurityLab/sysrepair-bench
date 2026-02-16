FROM navig/ubuntu:8.04

# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install Postfix with TLS support (vulnerable STARTTLS implementation)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postfix openssl

# Configure Postfix for TLS
RUN postconf -e "smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem" && \
    postconf -e "smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key" && \
    postconf -e "smtpd_use_tls=yes" && \
    postconf -e "smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache" && \
    postconf -e "smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache"

# Ubuntu 8.04 ships Postfix 2.5.1 which is vulnerable to CVE-2011-0411

EXPOSE 25

CMD ["postfix", "start-fg"]
