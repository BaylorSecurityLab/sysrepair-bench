FROM --platform=linux/amd64 hashicorp/consul:1.15.4

# HashiCorp Consul 1.15.4 with ACL system disabled.
# Any client — authenticated or not — can read, write, and delete every
# key in the KV store and query the service catalog without restriction.

USER root

RUN apk add --no-cache bash curl

RUN mkdir -p /consul/config /consul/data

COPY consul.hcl /consul/config/consul.hcl

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 8500 8600

CMD ["consul", "agent", "-server", "-bootstrap", "-ui", \
     "-data-dir=/consul/data", "-config-dir=/consul/config", \
     "-client=0.0.0.0"]
