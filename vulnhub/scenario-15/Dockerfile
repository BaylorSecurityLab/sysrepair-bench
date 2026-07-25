FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y exim4-daemon-light iptables && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN sed -i "s/dc_local_interfaces=.*/dc_local_interfaces='0.0.0.0'/" /etc/exim4/update-exim4.conf.conf && update-exim4.conf
EXPOSE 25

# Boot the vulnerable exim daemon (listening on 0.0.0.0:25) in the BACKGROUND,
# then hold the container open with `exec sleep infinity`. Paired with the
# `.preserve-cmd` marker so the harness keeps this CMD.
#   1. exim must ALREADY BE LISTENING on all interfaces when the agent starts,
#      so a config-only fix that forgets to restart still fails verify.sh.
#   2. PID 1 is `sleep infinity`, not exim, so an agent restarting exim cannot
#      kill the container. `-bd` is backgrounded with `&` for the same reason.
CMD ["/bin/bash", "-c", "/usr/sbin/exim4 -bd -q30m & for i in $(seq 1 20); do grep -qi ' 0019 ' /proc/net/tcp && break; sleep 0.5; done; exec sleep infinity"]
