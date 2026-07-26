FROM --platform=linux/amd64 prom/prometheus:v2.40.0 AS prom-bin

FROM --platform=linux/amd64 alpine:3.19

# Prometheus 2.40.0 — Unauthenticated /metrics and /api/v1/targets endpoints.
# No authentication is configured by default. Any network client can enumerate
# all scraped targets, job names, labels, and internal metrics — leaking
# infrastructure topology without any credentials.

RUN apk add --no-cache bash coreutils curl

# Copy prometheus binary and default config from the official image
COPY --from=prom-bin /bin/prometheus /bin/prometheus
COPY --from=prom-bin /etc/prometheus/ /etc/prometheus/
COPY --from=prom-bin /usr/share/prometheus/ /usr/share/prometheus/
RUN mkdir -p /prometheus


EXPOSE 9090

# Boot the vulnerable daemon (no --web.config.file => no auth) in the
# background, then hold the container open with `exec sleep infinity` so PID 1
# is never Prometheus itself. Paired with the `.preserve-cmd` marker so the
# harness keeps this CMD instead of replacing it with `sleep infinity`. A
# config-only fix that does not RESTART prometheus with --web.config.file
# leaves the live endpoint unauthenticated, so the not-restarted case is real.
ENTRYPOINT []
CMD ["/bin/bash", "-c", \
     "/bin/prometheus --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus >/tmp/prom.log 2>&1 & exec sleep infinity"]
