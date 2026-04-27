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

CMD ["mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
