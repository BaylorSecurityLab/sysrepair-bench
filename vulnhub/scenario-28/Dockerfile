FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN mkdir -p /tmp/staging /var/tmp/staging && chmod 777 /tmp/staging /var/tmp/staging
RUN printf '#!/bin/bash\necho "exploit"' > /tmp/staging/exploit.sh && chmod 755 /tmp/staging/exploit.sh
CMD ["/bin/bash"]
