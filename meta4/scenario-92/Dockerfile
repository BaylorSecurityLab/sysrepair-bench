FROM --platform=linux/amd64 prom/prometheus:v2.40.0

# Prometheus 2.40.0 — Unauthenticated /metrics and /api/v1/targets endpoints.
# No authentication is configured by default. Any network client can enumerate
# all scraped targets, job names, labels, and internal metrics — leaking
# infrastructure topology without any credentials.

USER root

# prom/prometheus is busybox-based; wget is available, curl is not
# No package manager — tools are already bundled in busybox

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 9090

ENTRYPOINT ["/bin/prometheus"]
CMD ["--config.file=/etc/prometheus/prometheus.yml", \
     "--storage.tsdb.path=/prometheus"]
