FROM --platform=linux/amd64 apache/activemq-classic:6.1.0

# ActiveMQ 6.1.0 exposes the Jolokia/REST API under /api/ without
# requiring authentication by default. CVE-2024-32114: any unauthenticated
# client can invoke Jolokia MBeans, read/write broker configuration,
# and interact with message queues via the REST API.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*


EXPOSE 61616 8161

CMD ["/bin/sh", "-c", "activemq start && tail -f /var/log/activemq/activemq.log"]
