FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y squid && apt-get clean && rm -rf /var/lib/apt/lists/*
# Open proxy (VULNERABLE)
RUN echo "http_port 3128\nhttp_access allow all\nacl all src 0.0.0.0/0" > /etc/squid/squid.conf
EXPOSE 3128
COPY verify.sh /verify.sh
CMD ["squid", "-N"]
