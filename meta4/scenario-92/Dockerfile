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

ENTRYPOINT ["/bin/prometheus"]
CMD ["--config.file=/etc/prometheus/prometheus.yml", \
     "--storage.tsdb.path=/prometheus"]
