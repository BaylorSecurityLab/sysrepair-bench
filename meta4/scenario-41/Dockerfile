FROM --platform=linux/amd64 couchdb:3.1

# CouchDB 3.1 with WEAK / WELL-KNOWN ADMIN CREDENTIALS (admin:admin).
#
# NOTE (scenario redesign): the original premise was "Admin Party" (empty
# [admins] => every request treated as admin).  CouchDB 3.0+ REMOVED Admin
# Party: the couchdb binary itself aborts startup with "No Admin Account Found"
# and the official docker-entrypoint refuses to boot without an admin.  Admin
# Party therefore CANNOT be reproduced on 3.1, and even with
# require_valid_user=false anonymous requests receive HTTP 401.  The faithful,
# genuinely-reproducible insecure-default on this version is a trivially
# guessable admin credential baked in by a lazy operator (admin:admin), which
# grants an unauthenticated network attacker full control of the HTTP API after
# one guess.  CWE-1188 / CWE-521.

USER root

# Redirect stale Debian repos to archive (couchdb:3.1 ships EOL sources)
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /stretch-updates/d; /buster-updates/d; /bullseye-updates/d' /etc/apt/sources.list 2>/dev/null; \
    sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g' /etc/apt/sources.list.d/*.list 2>/dev/null || true

RUN apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Bake the weak admin credential (admin:admin).  CouchDB hashes the plaintext
# value in-place on first boot; the plaintext still authenticates.  This is the
# vulnerable state: an attacker who guesses admin:admin owns the cluster.
RUN printf '\n[admins]\nadmin = admin\n' > /opt/couchdb/etc/local.d/vuln.ini && \
    chown -R couchdb:couchdb /opt/couchdb/etc

EXPOSE 5984

# Boot wrapper (paired with .preserve-cmd).  ENTRYPOINT is
# `tini -- /docker-entrypoint.sh`; because our CMD's $1 is /bin/bash (not
# "couchdb"), the entrypoint skips its couchdb setup and simply execs our
# wrapper.  We start couchdb ourselves (backgrounded, as the couchdb user via
# gosu) so:
#   * the daemon is ALREADY RUNNING with the weak credential when the agent
#     starts (the remediation must actively change the password, not just boot);
#   * PID 1 stays `sleep infinity`, so restarting couchdb never kills the
#     container.
CMD ["/bin/bash", "-c", "chown -R couchdb:couchdb /opt/couchdb/etc /opt/couchdb/data 2>/dev/null; gosu couchdb /opt/couchdb/bin/couchdb >/tmp/couchdb.log 2>&1 & for i in $(seq 1 60); do [ \"$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5984/_up 2>/dev/null)\" = 200 ] && break; sleep 1; done; exec sleep infinity"]
