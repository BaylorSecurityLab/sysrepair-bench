FROM --platform=linux/amd64 elasticsearch:7.10.1

# Elasticsearch 7.10.1 with X-Pack security disabled.
# The REST API on port 9200 is fully open: anyone can read, write, and
# delete indices, access cluster state, and enumerate all stored documents
# without supplying credentials.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

USER elasticsearch

ENV discovery.type=single-node
ENV xpack.security.enabled=false

EXPOSE 9200 9300

CMD ["/usr/local/bin/docker-entrypoint.sh", "eswrapper"]
