FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y ncat && apt-get clean && rm -rf /var/lib/apt/lists/*
# Custom service on all interfaces (VULNERABLE)
RUN printf '#!/bin/bash\nncat -l -k 0.0.0.0 8888 -e /bin/echo "Service OK"' > /usr/local/bin/custom-service.sh && chmod 755 /usr/local/bin/custom-service.sh
EXPOSE 8888
COPY verify.sh /verify.sh
CMD ["/usr/local/bin/custom-service.sh"]
