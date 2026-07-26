# Pinned by digest for a hermetic build. This is apache/kafka:latest as of the
# build date (Kafka 4.3.1, kafka_2.13-4.3.1). NOTE: the "3.5" in the scenario
# title is historical — the official apache/kafka image only exists from 3.7.0
# onward, so 3.5 was never available here. The misconfiguration graded (a
# PLAINTEXT client listener with no SASL authentication) is version-independent.
FROM --platform=linux/amd64 apache/kafka@sha256:77e3df9054047a88b520d0cc46e16696d3b22022e1d580aeccd2632df6532837

# Kafka default configuration uses a PLAINTEXT listener with no SASL
# authentication and no ACLs. Any client that can reach port 9092 can produce to
# or consume from any topic, including internal topics, with no credentials.

USER root

# apache/kafka is Alpine-based; nc is used by the boot wrapper and verify.sh.
RUN apk add --no-cache netcat-openbsd

EXPOSE 9092

# Fixed KRaft cluster id used to format the metadata log.
ENV CLUSTER_ID=MkU3OEVBNTcwNTJENDM2Qk

# Overwrite the stock config with the vulnerable PLAINTEXT baseline. The boot
# wrapper reads THIS file, and the solution rewrites THIS file then restarts the
# broker — so "edited config but forgot to restart" leaves the live broker still
# PLAINTEXT (detectable by the behavioural check).
COPY server-baseline.properties /opt/kafka/config/server.properties

# Boot wrapper (paired with the .preserve-cmd marker). The base image entrypoint
# (/__cacert_entrypoint.sh) execs this. We format the KRaft storage (idempotent),
# start the broker in the BACKGROUND, poll until 9092 binds, then exec
# `sleep infinity` so PID 1 is stable — a solution that stops/restarts the broker
# cannot kill the container.
CMD ["/bin/bash", "-c", "/opt/kafka/bin/kafka-storage.sh format -t \"$CLUSTER_ID\" -c /opt/kafka/config/server.properties --ignore-formatted; nohup /opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/server.properties >/var/log/kafka.log 2>&1 & for i in $(seq 1 60); do nc -z 127.0.0.1 9092 && break; sleep 1; done; exec sleep infinity"]
