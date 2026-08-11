FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates bash coreutils curl && rm -rf /var/lib/apt/lists/*
COPY bin/kimi /usr/local/bin/kimi
RUN chmod +x /usr/local/bin/kimi
ENV HOME=/root
WORKDIR /work
