FROM --platform=linux/amd64 bitnami/kafka:3.5

# Kafka 3.5 default configuration uses a PLAINTEXT listener with no
# SASL authentication and no ACLs. Any client that can reach port 9092
# can produce to or consume from any topic, including internal topics,
# with no credentials required.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 9092

ENV KAFKA_CFG_LISTENERS=PLAINTEXT://:9092
ENV KAFKA_CFG_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092
ENV ALLOW_PLAINTEXT_LISTENER=yes

CMD ["/opt/bitnami/scripts/kafka/run.sh"]
