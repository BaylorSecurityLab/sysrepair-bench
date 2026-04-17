FROM --platform=linux/amd64 ubuntu:22.04

# Password embedded in an ENV instruction is visible to anyone who runs
# `docker inspect` on the image or reads /proc/1/environ inside the container.
# ENV variables persist in every image layer and are trivially extractable.

ENV DB_PASSWORD=P@ssw0rd_2024

RUN apt-get update && \
    apt-get install -y --no-install-recommends bash && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/app

COPY app.sh /opt/app/app.sh
RUN chmod +x /opt/app/app.sh

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

CMD ["/opt/app/app.sh"]
