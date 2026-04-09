FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y exim4-daemon-light iptables && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN sed -i "s/dc_local_interfaces=.*/dc_local_interfaces='0.0.0.0'/" /etc/exim4/update-exim4.conf.conf && update-exim4.conf
EXPOSE 25
COPY verify.sh /verify.sh
CMD ["/usr/sbin/exim4", "-bd", "-q30m"]
