FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y ncat && apt-get clean && rm -rf /var/lib/apt/lists/*
# Custom service on all interfaces (VULNERABLE)
# NOTE: the original `-e /bin/echo "Service OK"` made ncat abort ("Got more than
# one port specification") so the service never bound - the vuln (0.0.0.0 bind)
# did not actually exist. Use --sh-exec so the service really listens.
RUN printf '#!/bin/bash\nexec ncat -l -k 0.0.0.0 8888 --sh-exec "echo Service OK"' > /usr/local/bin/custom-service.sh && chmod 755 /usr/local/bin/custom-service.sh
EXPOSE 8888
# Boot wrapper: start the service in the background, then exec sleep as PID 1 so a
# solution can restart it without killing the container (see .preserve-cmd).
CMD ["/bin/bash", "-c", "/usr/local/bin/custom-service.sh & exec sleep infinity"]
