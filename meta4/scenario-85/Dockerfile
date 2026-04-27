FROM --platform=linux/amd64 hashicorp/vault:1.13.3

# HashiCorp Vault 1.13.3 started in dev mode.
# Dev mode uses root token "root", no TLS, and in-memory storage —
# any process on the host can read/write every secret with a well-known token.

USER root

RUN apk add --no-cache bash procps curl coreutils


EXPOSE 8200

ENV VAULT_DEV_ROOT_TOKEN_ID=root
ENV VAULT_ADDR=http://127.0.0.1:8200

CMD ["vault", "server", "-dev", "-dev-listen-address=0.0.0.0:8200"]
