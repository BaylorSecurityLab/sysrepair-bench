FROM --platform=linux/amd64 apache/activemq-classic:5.17.5

# ActiveMQ 5.17.5 OpenWire protocol handler deserializes Java objects
# without class filtering by default. CVE-2023-46604 allows an
# unauthenticated attacker on port 61616 to trigger ClassPathXmlApplicationContext
# loading via a crafted ExceptionResponse, achieving remote code execution.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl netcat-openbsd iptables && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 61616 8161

CMD ["/bin/sh", "-c", "activemq start && tail -f /var/log/activemq/activemq.log"]
