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
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Download and install RocketMQ 5.1.0.
# Hermetic build: pin the archive with its published SHA-512 checksum.
RUN curl -fsSL \
    "https://archive.apache.org/dist/rocketmq/5.1.0/rocketmq-all-5.1.0-bin-release.zip" \
    -o /tmp/rocketmq.zip && \
    echo "ce754d03234260b35b0d14d4d7210f10150c6c063ff61d691874e0bec1b27197fa2020281cd1dfe7a8ab2ab1703264e57cc602ea3fb495f83cae1f5f810a5caa  /tmp/rocketmq.zip" | sha512sum -c - && \
    unzip -q /tmp/rocketmq.zip -d /opt && \
    mv /opt/rocketmq-all-5.1.0-bin-release /opt/rocketmq && \
    rm /tmp/rocketmq.zip

ENV ROCKETMQ_HOME=/opt/rocketmq
ENV PATH="${ROCKETMQ_HOME}/bin:${PATH}"

# Boot gotcha: RocketMQ ships with huge default JVM heaps (broker -Xms8g/-Xmx8g/-Xmn4g,
# nameserver -Xms4g/-Xmx4g) plus -XX:MaxDirectMemorySize=15g. On a normal machine the
# JVM fails to start and the service never comes up, making the scenario unusable.
# Shrink the heaps so NameServer + Broker boot in limited RAM.
RUN sed -i -E 's/-Xms[0-9]+[gm]/-Xms512m/g; s/-Xmx[0-9]+[gm]/-Xmx512m/g; s/-Xmn[0-9]+[gm]/-Xmn256m/g; s/-XX:MaxDirectMemorySize=[0-9]+[gm]/-XX:MaxDirectMemorySize=512m/g' \
        /opt/rocketmq/bin/runbroker.sh /opt/rocketmq/bin/runserver.sh

# Seed a vulnerable broker.conf — no ACL, no fileReservedTime override
RUN mkdir -p /opt/rocketmq/conf && \
    printf 'brokerClusterName=DefaultCluster\nbrokerName=broker-a\nbrokerId=0\nautoCreateTopicEnable=true\naclEnable=false\n' \
    > /opt/rocketmq/conf/broker.conf

EXPOSE 9876 10911

# Boot wrapper (paired with .preserve-cmd): start NameServer and Broker in the
# BACKGROUND, wait for the NameServer port, then exec `sleep infinity` so PID 1 is
# a stable process. A solution that restarts the broker cannot kill the container,
# and the not-restarted case (edited broker.conf but broker still running the old
# config) is detectable via the live iptables rule.
CMD ["/bin/bash", "-c", \
    "mqnamesrv >/var/log/mqnamesrv.log 2>&1 & \
     for i in $(seq 1 30); do nc -z localhost 9876 && break; sleep 2; done; \
     mqbroker -n localhost:9876 -c /opt/rocketmq/conf/broker.conf >/var/log/mqbroker.log 2>&1 & \
     for i in $(seq 1 60); do nc -z localhost 10911 && break; sleep 2; done; \
     exec sleep infinity"]
