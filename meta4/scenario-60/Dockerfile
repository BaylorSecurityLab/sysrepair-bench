FROM --platform=linux/amd64 debian:bookworm-slim

# Postfix 3.7 ships with default bare-LF handling that allows SMTP smuggling.
# An attacker can inject additional email messages past SPF/DKIM checks by
# embedding bare newlines (LF without CR) in the message body.

RUN apt-get update && \
    apt-get install -y --no-install-recommends postfix curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*


EXPOSE 25

CMD ["postfix", "start-fg"]
