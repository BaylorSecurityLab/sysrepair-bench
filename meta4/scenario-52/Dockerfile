FROM --platform=linux/amd64 alpine:3.19 AS tools
RUN apk add --no-cache netcat-openbsd bash

FROM --platform=linux/amd64 nats:2.7.1

# NATS 2.7.1 with no authentication configured. CVE-2022-24450: any
# unauthenticated client can connect and cross-switch into other
# accounts by exploiting the lack of authorization enforcement.
# Server listens on 0.0.0.0:4222 with no credentials required.

# nats:2.7.1 is scratch-based; bring in a shell + netcat from Alpine
COPY --from=tools /bin/sh /bin/sh
COPY --from=tools /usr/bin/nc /usr/bin/nc
COPY --from=tools /bin/bash /bin/bash
COPY --from=tools /lib/ld-musl-x86_64.so.1 /lib/ld-musl-x86_64.so.1
COPY --from=tools /usr/lib/libreadline.so* /usr/lib/
COPY --from=tools /usr/lib/libncursesw.so* /usr/lib/
COPY --from=tools /bin/cat /bin/cat
COPY --from=tools /bin/grep /bin/grep
COPY --from=tools /bin/sed /bin/sed
COPY --from=tools /bin/mkdir /bin/mkdir
COPY --from=tools /bin/chmod /bin/chmod
COPY --from=tools /usr/bin/printf /usr/bin/printf

COPY verify.sh /opt/verify.sh
RUN ["/bin/chmod", "+x", "/opt/verify.sh"]

# Seed a vulnerable config with no authorization block
RUN ["/bin/mkdir", "-p", "/etc/nats"]
RUN ["/bin/sh", "-c", "printf 'port: 4222\\nhttp_port: 8222\\n' > /etc/nats/nats-server.conf"]

EXPOSE 4222 8222

CMD ["nats-server", "-c", "/etc/nats/nats-server.conf"]
