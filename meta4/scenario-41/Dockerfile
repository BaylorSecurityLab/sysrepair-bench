FROM --platform=linux/amd64 couchdb:3.1

# CouchDB 3.1 in "Admin Party" mode: no admin account is configured.
# When the [admins] section in local.ini is empty, every incoming request
# is treated as if it were made by a server administrator.  Any unauthenticated
# HTTP client can create/delete databases, read all documents, and manage users.

USER root

# Redirect stale Debian repos to archive (couchdb:3.1 ships EOL sources)
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /stretch-updates/d; /buster-updates/d; /bullseye-updates/d' /etc/apt/sources.list 2>/dev/null; \
    sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g' /etc/apt/sources.list.d/*.list 2>/dev/null || true

RUN apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Explicitly unset the auto-created admin so Admin Party is guaranteed.
# The official image only creates an admin when COUCHDB_USER/PASSWORD are set.
ENV COUCHDB_USER=""
ENV COUCHDB_PASSWORD=""


EXPOSE 5984

CMD ["/opt/couchdb/bin/couchdb"]
