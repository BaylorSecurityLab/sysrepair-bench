FROM --platform=linux/amd64 apache/kafka:latest

# Kafka default configuration uses a PLAINTEXT listener with no
# SASL authentication and no ACLs. Any client that can reach port 9092
# can produce to or consume from any topic, including internal topics,
# with no credentials required.

USER root

# apache/kafka is Alpine-based
RUN apk add --no-cache netcat-openbsd

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 9092

ENV KAFKA_NODE_ID=1
ENV KAFKA_PROCESS_ROLES=broker,controller
ENV KAFKA_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093
ENV KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092
ENV KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER
ENV KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
ENV KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093
ENV KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1
ENV KAFKA_LOG_DIRS=/tmp/kraft-combined-logs
ENV CLUSTER_ID=MkU3OEVBNTcwNTJENDM2Qk

CMD ["/opt/kafka/bin/kafka-server-start.sh", "/opt/kafka/config/server.properties"]
