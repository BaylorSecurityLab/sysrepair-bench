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

# Boot wrapper (paired with the .preserve-cmd marker). `activemq start` daemonizes
# and returns, so we start it, poll until the web console on 8161 answers, then
# exec `sleep infinity` so PID 1 is stable and a solution that restarts the
# broker (to load the new jetty.xml) cannot kill the container.
CMD ["/bin/bash", "-c", "activemq start; for i in $(seq 1 90); do curl -s -o /dev/null http://127.0.0.1:8161/ && break; sleep 1; done; exec sleep infinity"]
