FROM navig/ubuntu:8.04

# Fix old repository URLs
RUN sed -i 's|archive.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list && \
    sed -i 's|security.ubuntu.com|old-releases.ubuntu.com|g' /etc/apt/sources.list

# Install PostgreSQL
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-client && \
    apt-get clean

# Start PostgreSQL temporarily to configure it
# Set weak password for postgres user and configure remote access
RUN /etc/init.d/postgresql-8.3 start && \
    sleep 2 && \
    su - postgres -c "psql -c \"ALTER USER postgres WITH PASSWORD 'postgres';\"" && \
    /etc/init.d/postgresql-8.3 stop

# Configure PostgreSQL to listen on all interfaces (the vulnerability)
RUN sed -i "s/^#*listen_addresses\s*=.*/listen_addresses = '*'/" /etc/postgresql/8.3/main/postgresql.conf

# Allow remote connections with md5 authentication (weak password is exploitable remotely)
RUN echo "host    all    all    0.0.0.0/0    md5" >> /etc/postgresql/8.3/main/pg_hba.conf

# Expose PostgreSQL port
EXPOSE 5432

# Start PostgreSQL as the postgres user
CMD su - postgres -c "/usr/lib/postgresql/8.3/bin/postgres -D /etc/postgresql/8.3/main"
