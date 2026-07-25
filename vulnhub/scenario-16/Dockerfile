FROM debian:11

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y knockd && apt-get clean && rm -rf /var/lib/apt/lists/*

# Insecure knockd config (VULNERABLE)
RUN echo "[options]" > /etc/knockd.conf && \
    echo "    logfile = /var/log/knockd.log" >> /etc/knockd.conf && \
    echo "" >> /etc/knockd.conf && \
    echo "[openSSH]" >> /etc/knockd.conf && \
    echo "    sequence = 1000,2000,3000" >> /etc/knockd.conf && \
    echo "    seq_timeout = 30" >> /etc/knockd.conf && \
    echo "    command = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT" >> /etc/knockd.conf && \
    echo "    tcpflags = syn" >> /etc/knockd.conf


# Boot wrapper: start knockd in the background, then hand PID 1 to sleep so a
# solution can restart knockd without killing the container (see .preserve-cmd).
CMD ["/bin/bash", "-c", "knockd & exec sleep infinity"]
