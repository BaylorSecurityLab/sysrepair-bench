FROM --platform=linux/amd64 debian:bookworm-slim

# RocketMQ 5.1.0 — Unauthenticated config update via broker port 10911
# allows an attacker to modify broker configuration and trigger filter
# server RCE via CVE-2023-33246. This image runs NameServer + Broker
# with no ACL and no iptables restrictions by default.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        netcat-openbsd \
        iptables \
        default-jre-headless \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Download and install RocketMQ 5.1.0
RUN curl -fsSL \
    "https://archive.apache.org/dist/rocketmq/5.1.0/rocketmq-all-5.1.0-bin-release.zip" \
    -o /tmp/rocketmq.zip && \
    apt-get update && apt-get install -y --no-install-recommends unzip && \
    rm -rf /var/lib/apt/lists/* && \
    unzip /tmp/rocketmq.zip -d /opt && \
    mv /opt/rocketmq-all-5.1.0-bin-release /opt/rocketmq && \
    rm /tmp/rocketmq.zip

ENV ROCKETMQ_HOME=/opt/rocketmq
ENV PATH="${ROCKETMQ_HOME}/bin:${PATH}"

# Seed a vulnerable broker.conf — no ACL, no fileReservedTime override
RUN mkdir -p /opt/rocketmq/conf && \
    printf 'brokerClusterName=DefaultCluster\nbrokerName=broker-a\nbrokerId=0\nautoCreateTopicEnable=true\naclEnable=false\n' \
    > /opt/rocketmq/conf/broker.conf

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 9876 10911

# Start NameServer in background, then Broker in foreground
CMD ["/bin/sh", "-c", \
    "mqnamesrv & sleep 5 && mqbroker -n localhost:9876 -c /opt/rocketmq/conf/broker.conf"]
