FROM --platform=linux/amd64 eclipse-mosquitto:2.0

# Mosquitto 2.0 default configuration requires allow_anonymous to be
# explicitly set. When set to true (or left unconfigured with a permissive
# default), any client can connect without credentials and publish or
# subscribe to any topic. No TLS, no ACLs.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends mosquitto-clients netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

# Seed a vulnerable configuration
RUN echo "listener 1883" > /mosquitto/config/mosquitto.conf && \
    echo "allow_anonymous true" >> /mosquitto/config/mosquitto.conf && \
    echo "persistence false" >> /mosquitto/config/mosquitto.conf

EXPOSE 1883

CMD ["mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
