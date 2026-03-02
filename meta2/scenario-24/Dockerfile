FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install Postfix with TLS support
# Ubuntu 8.04 ships with OpenSSL 0.9.8g which supports EXPORT cipher suites
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postfix openssl

# Configure Postfix for TLS with weak export ciphers allowed
RUN postconf -e "smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem" && \
    postconf -e "smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key" && \
    postconf -e "smtpd_use_tls=yes" && \
    postconf -e "smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache" && \
    postconf -e "smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache"

# Old OpenSSL 0.9.8g accepts RSA_EXPORT (FREAK - CVE-2015-0204) and
# DHE_EXPORT (LogJam - CVE-2015-4000) cipher suites by default

EXPOSE 25

CMD ["postfix", "start-fg"]
