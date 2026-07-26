FROM --platform=linux/amd64 hashicorp/vault:1.13.3

# HashiCorp Vault 1.13.3 started in dev mode.
# Dev mode uses root token "root", no TLS, and in-memory storage —
# any process on the host can read/write every secret with a well-known token.

USER root

RUN apk add --no-cache bash procps curl coreutils

RUN mkdir -p /vault/data /vault/config

COPY start.sh /opt/start.sh
RUN chmod +x /opt/start.sh

EXPOSE 8200

ENV VAULT_DEV_ROOT_TOKEN_ID=root
ENV VAULT_ADDR=http://127.0.0.1:8200

# Boot Vault (in -dev mode = the vuln) via a wrapper that keeps PID 1 as
# `sleep infinity`, so a solution can restart Vault as a non-dev server.
ENTRYPOINT []
CMD ["/opt/start.sh"]
