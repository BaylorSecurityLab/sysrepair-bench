FROM --platform=linux/amd64 rabbitmq:3.11-management

# RabbitMQ management image ships with guest/guest credentials and
# sets loopback_users.guest = false, making the default creds
# accessible from any IP. Management UI exposed on 15672.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/rabbitmq && \
    printf 'loopback_users.guest = false\n' > /etc/rabbitmq/rabbitmq.conf

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 5672 15672

CMD ["rabbitmq-server"]
