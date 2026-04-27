FROM --platform=linux/amd64 couchdb:3.2.1

# CouchDB 3.2.1 ships with the Erlang distribution cookie set to "monster"
# in /opt/couchdb/etc/vm.args.  CVE-2022-24706: any attacker who knows this
# cookie can connect to the Erlang Port Mapper Daemon (EPMD) and the
# distribution port, execute arbitrary Erlang terms, and achieve unauthenticated
# remote code execution as the couchdb user.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Confirm the default cookie is in place (it is in the upstream image,
# but we make it explicit so the vulnerable state is unambiguous).
RUN grep -q 'monster' /opt/couchdb/etc/vm.args || \
    sed -i 's/^-setcookie .*/\-setcookie monster/' /opt/couchdb/etc/vm.args


EXPOSE 5984 4369

CMD ["/opt/couchdb/bin/couchdb"]
