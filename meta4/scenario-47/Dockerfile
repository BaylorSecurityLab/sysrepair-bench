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


EXPOSE 5672 15672

# Boot wrapper (paired with the .preserve-cmd marker). The image entrypoint ends
# in `exec "$@"` and the container runs as root, so this runs rabbitmq-server as
# root (as the stock CMD did). Start it in the background, wait for the
# management API on 15672 to answer, then exec `sleep infinity` so PID 1 is
# stable and rabbitmqctl actions cannot kill the container.
CMD ["/bin/bash", "-c", "rabbitmq-server & for i in $(seq 1 90); do [ -n \"$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:15672/api/overview 2>/dev/null | grep -E '^(200|401)$')\" ] && break; sleep 1; done; exec sleep infinity"]
