FROM --platform=linux/amd64 cassandra:3.11

# Cassandra 3.11 defaults to AllowAllAuthenticator (no credentials required)
# and AllowAllAuthorizer (no permission checks).  CVE-2021-44521: when
# enable_user_defined_functions is also set to true, any connected client
# can execute arbitrary Java code server-side via a UDF, achieving RCE.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Ensure the vulnerable defaults are explicitly present in cassandra.yaml
RUN sed -i \
        -e 's/^authenticator:.*/authenticator: AllowAllAuthenticator/' \
        -e 's/^authorizer:.*/authorizer: AllowAllAuthorizer/' \
        /etc/cassandra/cassandra.yaml && \
    grep -q 'enable_user_defined_functions' /etc/cassandra/cassandra.yaml && \
    sed -i 's/^enable_user_defined_functions:.*/enable_user_defined_functions: true/' \
        /etc/cassandra/cassandra.yaml || \
    echo 'enable_user_defined_functions: true' >> /etc/cassandra/cassandra.yaml

EXPOSE 9042

# Boot wrapper (paired with .preserve-cmd).  The image ENTRYPOINT
# (docker-entrypoint.sh) only performs its chown + gosu-to-cassandra step when
# $1 == "cassandra"; our CMD's $1 is /bin/bash, so the entrypoint just execs
# this wrapper AS ROOT.  We therefore replicate the chown and drop to the
# cassandra user via gosu ourselves, start Cassandra in the background, poll
# until CQL is answering, then exec sleep infinity.  PID 1 stays sleep infinity
# so restarting Cassandra never kills the container; the fix must RESTART it.
CMD ["/bin/bash", "-c", "find /etc/cassandra /var/lib/cassandra /var/log/cassandra ! -user cassandra -exec chown cassandra {} + 2>/dev/null; gosu cassandra cassandra -f >/var/log/cassandra/boot.log 2>&1 & for i in $(seq 1 120); do cqlsh -u cassandra -p cassandra localhost -e 'DESCRIBE KEYSPACES' >/dev/null 2>&1 && break; sleep 3; done; exec sleep infinity"]
