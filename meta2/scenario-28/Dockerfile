FROM sysrepair/meta2-hardy:latest
# Fix package repositories to use old-releases
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install Postfix (SMTP) and PostgreSQL with SSL support.
# python-openssl (pyOpenSSL) lets the verifier pull PostgreSQL's live server
# certificate off the wire (after the SSLRequest handshake) and inspect it.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        postfix \
        postgresql \
        openssl python-openssl && \
    apt-get clean

# Generate an SSL certificate signed with the weak SHA-1 algorithm.
RUN openssl req -x509 -sha1 -newkey rsa:2048 \
    -keyout /etc/ssl/private/weak.key \
    -out /etc/ssl/certs/weak.crt \
    -days 365 -nodes \
    -subj "/CN=localhost/O=Weak SHA1 Cert"

# Configure Postfix to use the SHA-1 signed certificate. An oversized max_idle
# keeps the warm smtpd alive well past any harness run so the "edited main.cf
# but never reloaded" case stays detectable — the warm child keeps serving the
# SHA-1 cert until `postfix reload` cycles it. (1000s let it die mid-run.)
RUN postconf -e 'smtpd_tls_cert_file = /etc/ssl/certs/weak.crt' && \
    postconf -e 'smtpd_tls_key_file = /etc/ssl/private/weak.key' && \
    postconf -e 'smtpd_use_tls = yes' && \
    postconf -e 'max_idle = 100000s' && \
    postconf -e 'smtpd_tls_security_level = may'

# Configure PostgreSQL to use the SHA-1 certificate. PostgreSQL 8.3 reads
# server.crt/server.key from its DATA directory (not /etc/postgresql), so the
# weak cert MUST be installed there to actually be served on the wire.
RUN sed -i "s/^#*ssl[[:space:]]*=.*/ssl = true/" /etc/postgresql/8.3/main/postgresql.conf && \
    rm -f /var/lib/postgresql/8.3/main/server.crt /var/lib/postgresql/8.3/main/server.key && \
    cp /etc/ssl/certs/weak.crt /var/lib/postgresql/8.3/main/server.crt && \
    cp /etc/ssl/private/weak.key /var/lib/postgresql/8.3/main/server.key && \
    chown postgres:postgres /var/lib/postgresql/8.3/main/server.crt /var/lib/postgresql/8.3/main/server.key && \
    chmod 600 /var/lib/postgresql/8.3/main/server.key

# Boot wrapper: start PostgreSQL (as postgres) and Postfix in the BACKGROUND,
# prime a warm smtpd, then keep PID 1 as `sleep infinity`.
RUN printf '%s\n' \
    '#!/bin/bash' \
    "su postgres -c '/usr/lib/postgresql/8.3/bin/postgres -D /var/lib/postgresql/8.3/main -c config_file=/etc/postgresql/8.3/main/postgresql.conf' &" \
    'postfix start' \
    'for i in $(seq 1 20); do printf "EHLO warm\r\nQUIT\r\n" | nc -w2 127.0.0.1 25 2>/dev/null | grep -q "^220" && break; sleep 1; done' \
    'exec sleep infinity' \
    > /start.sh && chmod +x /start.sh

EXPOSE 25 5432

CMD ["/start.sh"]
