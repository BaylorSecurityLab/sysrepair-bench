FROM --platform=linux/amd64 debian:bookworm-slim

# Postfix 3.7 ships with default bare-LF handling that allows SMTP smuggling.
# An attacker can inject additional email messages past SPF/DKIM checks by
# embedding bare newlines (LF without CR) in the message body.

RUN apt-get update && \
    apt-get install -y --no-install-recommends postfix curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*


EXPOSE 25

# Boot wrapper (see .preserve-cmd): start the Postfix master in the BACKGROUND
# (`postfix start` daemonizes) then exec `sleep infinity` so PID 1 is the
# wrapper. The vulnerable SMTP service is already listening on :25 when the agent
# starts, and a solution that reloads/restarts Postfix cannot kill the container.
CMD ["/bin/bash", "-c", "postfix start && exec sleep infinity"]
