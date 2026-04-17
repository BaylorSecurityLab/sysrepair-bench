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

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 9042

CMD ["cassandra", "-f"]
