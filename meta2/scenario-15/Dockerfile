FROM sysrepair/meta2-hardy:latest
# Install distcc and gcc
RUN apt-get update && \
    apt-get install -y distcc gcc net-tools && \
    apt-get clean

# Create distcc user if it does not exist
RUN id distccd 2>/dev/null || useradd -r -s /bin/false distccd

# Boot wrapper: distccd 2.18.3 makes --allow mandatory, so the UNRESTRICTED
# posture is expressed as `--allow 0.0.0.0/0` (accept every host, including the
# loopback our PoC connects from). This reproduces CVE-2004-2687: any allowed
# client can drive the compiler argv to run arbitrary commands. The daemon runs
# in the BACKGROUND and PID 1 stays `sleep infinity` so a restart can't kill the
# container. A .preserve-cmd marker makes the harness run this CMD.
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'distccd --daemon --no-detach --user distccd --port 3632 --allow 0.0.0.0/0 --log-file /var/log/distccd.log &' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 3632

CMD ["/start.sh"]
