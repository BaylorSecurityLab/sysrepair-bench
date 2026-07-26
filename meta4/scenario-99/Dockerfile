FROM --platform=linux/amd64 eclipse-temurin:11-jre-jammy

# Hadoop YARN 3.3.4 — Unauthenticated ResourceManager RCE (CWE-306)
# The ResourceManager REST API on port 8088 has no authentication by default.
# Anyone with network access can submit a YARN application via POST to
# /ws/v1/cluster/apps, achieving unauthenticated RCE on all NodeManagers.
# Remediation: enable Kerberos auth, configure yarn.acl.enable + ACLs,
# restrict port 8088 to trusted hosts only.
#
# NB: Hadoop 3.3.4 supports Java 8/11 ONLY. On Java 17 the ResourceManager dies
# at startup with InaccessibleObjectException (java.base module encapsulation),
# so the vulnerable daemon never runs. We pin a Java 11 base so the RM actually
# starts.

ENV DEBIAN_FRONTEND=noninteractive \
    HADOOP_VERSION=3.3.4 \
    HADOOP_HOME=/opt/hadoop \
    JAVA_HOME=/opt/java/openjdk

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget ca-certificates \
        netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Integrity gate: the fetch is non-hermetic (live archive.apache.org), so the
# exact tarball is sha256-pinned. sha256 of hadoop-3.3.4.tar.gz; cross-verified
# against Apache's published .sha512. A corrupted or substituted download fails
# `sha256sum -c -` here and the build aborts before extraction.
RUN wget -q "https://archive.apache.org/dist/hadoop/common/hadoop-${HADOOP_VERSION}/hadoop-${HADOOP_VERSION}.tar.gz" \
        -O /tmp/hadoop.tar.gz && \
    echo "6a483d1a0b123490ebd8df3f71b64eb39f333f78b95f090aeb58e433cbc2416d  /tmp/hadoop.tar.gz" | sha256sum -c - && \
    tar xzf /tmp/hadoop.tar.gz -C /opt && \
    mv /opt/hadoop-${HADOOP_VERSION} ${HADOOP_HOME} && \
    rm /tmp/hadoop.tar.gz

# Vulnerable config: no auth on ResourceManager REST API
RUN cat > ${HADOOP_HOME}/etc/hadoop/yarn-site.xml <<'EOF'
<?xml version="1.0"?>
<configuration>
  <!-- VULNERABLE: no ACL enforcement, no auth -->
  <property>
    <name>yarn.acl.enable</name>
    <value>false</value>
  </property>
  <property>
    <name>yarn.resourcemanager.webapp.address</name>
    <value>0.0.0.0:8088</value>
  </property>
</configuration>
EOF


EXPOSE 8088

# Boot the ResourceManager (unauthenticated REST API on 8088) in the background,
# then hold the container open with `exec sleep infinity` so the RM is never
# PID 1. Paired with the `.preserve-cmd` marker. A fix that edits config but
# never restarts the RM leaves the live 8088 API unauthenticated, so the
# not-restarted case is real.
CMD ["bash", "-c", "${HADOOP_HOME}/bin/yarn --daemon start resourcemanager; exec sleep infinity"]
