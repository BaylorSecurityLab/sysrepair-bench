FROM --platform=linux/amd64 eclipse-mosquitto:2.0

# Mosquitto 2.0 default configuration requires allow_anonymous to be
# explicitly set. When set to true (or left unconfigured with a permissive
# default), any client can connect without credentials and publish or
# subscribe to any topic. No TLS, no ACLs.

USER root

# eclipse-mosquitto is Alpine-based
RUN apk add --no-cache mosquitto-clients netcat-openbsd


# Seed a vulnerable configuration
RUN echo "listener 1883" > /mosquitto/config/mosquitto.conf && \
    echo "allow_anonymous true" >> /mosquitto/config/mosquitto.conf && \
    echo "persistence false" >> /mosquitto/config/mosquitto.conf

EXPOSE 1883

# Boot wrapper: start the broker daemonized (-d double-forks so it survives),
# poll for :1883, then exec `sleep infinity` so PID 1 is stable and an agent
# restarting mosquitto cannot kill the container. See .preserve-cmd.
CMD ["/bin/sh", "-c", "mosquitto -c /mosquitto/config/mosquitto.conf -d; for i in $(seq 1 30); do nc -z 127.0.0.1 1883 && break; sleep 1; done; exec sleep infinity"]
