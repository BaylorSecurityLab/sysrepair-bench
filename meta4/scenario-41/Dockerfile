FROM --platform=linux/amd64 couchdb:3.1

# CouchDB 3.1 in "Admin Party" mode: no admin account is configured.
# When the [admins] section in local.ini is empty, every incoming request
# is treated as if it were made by a server administrator.  Any unauthenticated
# HTTP client can create/delete databases, read all documents, and manage users.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Explicitly unset the auto-created admin so Admin Party is guaranteed.
# The official image only creates an admin when COUCHDB_USER/PASSWORD are set.
ENV COUCHDB_USER=""
ENV COUCHDB_PASSWORD=""

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 5984

CMD ["/opt/couchdb/bin/couchdb"]
