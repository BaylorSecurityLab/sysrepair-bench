FROM --platform=linux/amd64 lpenz/ubuntu-hardy-amd64

# Fix old repository URLs
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install Postfix (SMTP) and PostgreSQL with SSL support
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        postfix \
        postgresql \
        openssl && \
    apt-get clean

# Generate an expired SSL certificate (valid for only 1 day, backdated)
# Create cert that expired in the past
RUN openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/ssl/private/expired.key \
    -out /etc/ssl/certs/expired.crt \
    -days 1 -nodes \
    -subj "/CN=localhost/O=Expired Cert" && \
    # Backdate the certificate by faking system time is not possible in Docker,
    # so we create a cert that will appear as short-lived (1 day)
    # For a truly expired cert, use faketime or openssl with explicit dates
    openssl x509 -in /etc/ssl/certs/expired.crt -out /etc/ssl/certs/expired_backdated.crt \
        -signkey /etc/ssl/private/expired.key -days 0 2>/dev/null || \
    # Alternative: create cert with explicit past dates using openssl ca features
    openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/ssl/private/expired.key \
        -out /etc/ssl/certs/expired.crt \
        -nodes -subj "/CN=localhost/O=Expired Cert" \
        -set_serial 1 \
        -days 0

# Configure Postfix to use the expired SSL certificate
RUN postconf -e 'smtpd_tls_cert_file = /etc/ssl/certs/expired.crt' && \
    postconf -e 'smtpd_tls_key_file = /etc/ssl/private/expired.key' && \
    postconf -e 'smtpd_use_tls = yes' && \
    postconf -e 'smtpd_tls_security_level = may'

# Configure PostgreSQL to use the expired SSL certificate
RUN mkdir -p /etc/postgresql/8.3/main && \
    cp /etc/ssl/certs/expired.crt /etc/postgresql/8.3/main/server.crt && \
    cp /etc/ssl/private/expired.key /etc/postgresql/8.3/main/server.key && \
    chown postgres:postgres /etc/postgresql/8.3/main/server.crt \
        /etc/postgresql/8.3/main/server.key && \
    chmod 600 /etc/postgresql/8.3/main/server.key

# Enable SSL in PostgreSQL
RUN if [ -f /etc/postgresql/8.3/main/postgresql.conf ]; then \
        sed -i "s/^#*ssl[[:space:]]*=.*/ssl = true/" /etc/postgresql/8.3/main/postgresql.conf; \
    fi

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo '/etc/init.d/postgresql-8.3 start 2>/dev/null || /etc/init.d/postgresql start 2>/dev/null || true' >> /start.sh && \
    echo '/usr/sbin/postfix start' >> /start.sh && \
    echo 'tail -f /var/log/mail.log 2>/dev/null || sleep infinity' >> /start.sh && \
    chmod +x /start.sh

# Expose SMTP and PostgreSQL ports
EXPOSE 25 5432

CMD ["/start.sh"]
