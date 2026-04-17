FROM --platform=linux/amd64 elasticsearch:7.10.1

# Elasticsearch 7.10.1 with X-Pack security disabled.
# The REST API on port 9200 is fully open: anyone can read, write, and
# delete indices, access cluster state, and enumerate all stored documents
# without supplying credentials.

USER root

# elasticsearch:7.10.1 is CentOS 8 (EOL) — redirect to vault
RUN sed -i 's|mirrorlist=|#mirrorlist=|g; s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo
RUN yum install -y curl && yum clean all

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

USER elasticsearch

ENV discovery.type=single-node
ENV xpack.security.enabled=false

EXPOSE 9200 9300

CMD ["/usr/local/bin/docker-entrypoint.sh", "eswrapper"]
