FROM --platform=linux/amd64 hashicorp/consul:1.15.4

# HashiCorp Consul 1.15.4 with ACL system disabled.
# Any client — authenticated or not — can read, write, and delete every
# key in the KV store and query the service catalog without restriction.

USER root

RUN apk add --no-cache bash curl

RUN mkdir -p /consul/config /consul/data

COPY consul.hcl /consul/config/consul.hcl

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 8500 8600

# Boot Consul via a wrapper that keeps PID 1 as `sleep infinity` so a solution
# can restart Consul (required to apply ACLs) without killing the container.
ENTRYPOINT []
CMD ["/opt/start.sh"]
