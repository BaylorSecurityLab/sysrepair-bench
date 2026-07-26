FROM --platform=linux/amd64 elasticsearch:7.10.1

# Elasticsearch 7.10.1 with X-Pack security disabled.
# The REST API on port 9200 is fully open: anyone can read, write, and
# delete indices, access cluster state, and enumerate all stored documents
# without supplying credentials.

USER root

# elasticsearch:7.10.1 is CentOS 8 (EOL) — redirect to vault
RUN sed -i 's|mirrorlist=|#mirrorlist=|g; s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo
RUN yum install -y curl && yum clean all

USER elasticsearch

ENV discovery.type=single-node
# NB: do NOT bake `ENV xpack.security.enabled=false`. bin/elasticsearch turns
# dotted ES-setting env vars into -E command-line flags, which OVERRIDE
# elasticsearch.yml — so a baked false would make the correct remediation
# (setting the yml to true and restarting) a no-op, punishing the right fix.
# ES 7.10 (basic license) defaults security to DISABLED anyway, so the baseline
# is vulnerable without the env var, and the yml edit in the fix now takes hold.

EXPOSE 9200 9300

# Boot wrapper (paired with .preserve-cmd).  Image USER is elasticsearch, so
# this wrapper runs as the elasticsearch user (ES refuses to run as root).  We
# start ES in the background (security defaults to disabled on a 7.10 basic
# license, so the API is wide open), poll until :9200 answers, then exec sleep
# infinity.  PID 1 stays sleep infinity so restarting ES never kills the
# container; the fix must enable security AND RESTART ES.  -Ediscovery.type is
# passed explicitly because bin/elasticsearch (unlike the eswrapper entrypoint)
# reads the dotted `discovery.type` ENV above as a setting, so we must NOT also
# pass -Ediscovery.type or ES aborts with "setting [discovery.type] already
# set". The ENV is the single source of truth.
CMD ["/bin/bash", "-c", "/usr/share/elasticsearch/bin/elasticsearch >/tmp/es.log 2>&1 & for i in $(seq 1 90); do curl -s -o /dev/null http://localhost:9200 && break; sleep 2; done; exec sleep infinity"]
