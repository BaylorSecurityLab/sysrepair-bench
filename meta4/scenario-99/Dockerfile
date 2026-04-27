FROM --platform=linux/amd64 debian:bookworm-slim

# Hadoop YARN 3.3.4 — Unauthenticated ResourceManager RCE (CWE-306)
# The ResourceManager REST API on port 8088 has no authentication by default.
# Anyone with network access can submit a YARN application via POST to
# /ws/v1/cluster/apps, achieving unauthenticated RCE on all NodeManagers.
# Remediation: enable Kerberos auth, configure yarn.acl.enable + ACLs,
# restrict port 8088 to trusted hosts only.

ENV DEBIAN_FRONTEND=noninteractive \
    HADOOP_VERSION=3.3.4 \
    HADOOP_HOME=/opt/hadoop \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget ca-certificates \
        openjdk-17-jre-headless \
        netcat-traditional && \
    rm -rf /var/lib/apt/lists/*

RUN wget -q "https://archive.apache.org/dist/hadoop/common/hadoop-${HADOOP_VERSION}/hadoop-${HADOOP_VERSION}.tar.gz" \
        -O /tmp/hadoop.tar.gz && \
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

CMD ["bash", "-c", "${HADOOP_HOME}/sbin/start-yarn.sh && tail -f ${HADOOP_HOME}/logs/*.log 2>/dev/null || sleep infinity"]
