FROM --platform=linux/amd64 grafana/grafana:8.3.0

# Grafana 8.3.0 — CVE-2021-43798: Plugin path traversal allows unauthenticated
# reads of arbitrary local files via /public/plugins/<name>/../../../../etc/passwd.
# The vulnerable endpoint requires no authentication.

USER root

# grafana:8.3.0 is Alpine-based
RUN apk add --no-cache curl nginx coreutils


EXPOSE 3000

# Boot the vulnerable Grafana (8.3.0, path-traversal in the plugin static
# handler) in the background on port 3000, then hold the container open with
# `exec sleep infinity` so Grafana is never PID 1. Paired with the
# `.preserve-cmd` marker so the harness keeps this CMD. The compensating-control
# fix stands up an nginx sanitising proxy on 3000 and moves Grafana behind it;
# a fix that edits config but never starts the proxy leaves 3000 traversable, so
# the not-restarted case is real.
ENTRYPOINT []
CMD ["/bin/bash", "-c", \
     "/usr/share/grafana/bin/grafana-server --homepath=/usr/share/grafana --config=/etc/grafana/grafana.ini >/tmp/grafana.log 2>&1 & exec sleep infinity"]
