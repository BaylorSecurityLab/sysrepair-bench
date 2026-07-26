FROM --platform=linux/amd64 apache/activemq-classic:5.17.6

# ActiveMQ 5.17.5 OpenWire protocol handler deserializes Java objects
# without class filtering by default. CVE-2023-46604 allows an
# unauthenticated attacker on port 61616 to trigger ClassPathXmlApplicationContext
# loading via a crafted ExceptionResponse, achieving remote code execution.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl netcat-openbsd iptables && \
    rm -rf /var/lib/apt/lists/*


EXPOSE 61616 8161

# Boot wrapper (paired with the .preserve-cmd marker). `activemq start` daemonizes
# and returns, so we start it, poll until the web console on 8161 answers, then
# exec `sleep infinity` so PID 1 is stable and a solution that adds an iptables
# rule (or restarts the broker) cannot kill the container.
CMD ["/bin/bash", "-c", "activemq start; for i in $(seq 1 90); do curl -s -o /dev/null http://127.0.0.1:8161/ && break; sleep 1; done; exec sleep infinity"]
