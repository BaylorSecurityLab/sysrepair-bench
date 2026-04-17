FROM --platform=linux/amd64 grafana/grafana:8.3.0

# Grafana 8.3.0 — CVE-2021-43798: Plugin path traversal allows unauthenticated
# reads of arbitrary local files via /public/plugins/<name>/../../../../etc/passwd.
# The vulnerable endpoint requires no authentication.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl nginx && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 3000

CMD ["/usr/share/grafana/bin/grafana-server", \
     "--homepath=/usr/share/grafana", \
     "--config=/etc/grafana/grafana.ini"]
