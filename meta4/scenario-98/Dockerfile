FROM --platform=linux/amd64 debian:bookworm-slim

# Apache Druid 0.20.2 — CVE-2021-25646: JavaScript injection in DataSource
# input filter. When druid.javascript.enabled=true, the coordinator accepts
# JavaScript function bodies in query filter expressions and executes them
# server-side — enabling unauthenticated RCE via a crafted HTTP POST.
# Remediation: set druid.javascript.enabled=false in runtime.properties.

ENV DEBIAN_FRONTEND=noninteractive \
    DRUID_VERSION=0.20.2 \
    DRUID_HOME=/opt/druid

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget ca-certificates \
        openjdk-17-jre-headless perl netcat-traditional && \
    rm -rf /var/lib/apt/lists/*

# Download and install Druid 0.20.2
RUN wget -q "https://archive.apache.org/dist/druid/${DRUID_VERSION}/apache-druid-${DRUID_VERSION}-bin.tar.gz" \
        -O /tmp/druid.tar.gz && \
    tar xzf /tmp/druid.tar.gz -C /opt && \
    mv /opt/apache-druid-${DRUID_VERSION} ${DRUID_HOME} && \
    rm /tmp/druid.tar.gz

# Vulnerable default: JavaScript enabled
RUN echo "druid.javascript.enabled=true" >> ${DRUID_HOME}/conf/druid/single-server/nano-quickstart/coordinator-overlord/runtime.properties


EXPOSE 8081

CMD ["bash", "-c", "${DRUID_HOME}/bin/start-nano-quickstart"]
