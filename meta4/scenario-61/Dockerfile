FROM --platform=linux/amd64 debian:bullseye-slim

# Exim 4.96 advertises CHUNKING and PIPELINING by default, enabling SMTP
# smuggling attacks (CVE-2023-51766) that can bypass SPF/DKIM checks.

RUN apt-get update && \
    apt-get install -y --no-install-recommends exim4 curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 25

CMD ["exim4", "-bdf", "-q30m"]
