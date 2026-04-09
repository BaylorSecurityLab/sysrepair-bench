FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y cron && apt-get clean && rm -rf /var/lib/apt/lists/*
# Root cron executes from /tmp (VULNERABLE)
RUN printf '#!/bin/bash\necho "cleanup" > /dev/null' > /tmp/cleanup.sh && chmod 755 /tmp/cleanup.sh
RUN echo "* * * * * root /tmp/cleanup.sh" > /etc/cron.d/vulnerable-cleanup
COPY verify.sh /verify.sh
CMD ["cron", "-f"]
