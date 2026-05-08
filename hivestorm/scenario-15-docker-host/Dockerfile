# Hivestorm scenario-15 — Docker host hardening (dockerd-in-container).
#
# Build contract:
#   python -m hivestorm.common.roles --scenario 15 --seed $RANDOM \
#     --out hivestorm/scenario-15-docker-host/build/roles.json \
#     --render-task hivestorm/scenario-15-docker-host/task.md
#   docker build hivestorm/scenario-15-docker-host
#
# Runtime MUST be launched with `--privileged` on the outer engine so the
# inner dockerd can create namespaces and mount overlayfs. The scenario
# itself exists *to teach the agent to remove `--privileged`* on the inner
# workload container — the outer-privileged bit is a container-in-container
# necessity, not part of the scored surface.
#
# The docker:dind base already ships dockerd + client; seed.sh layers on
# misconfigured daemon.json, user accounts, and the inner workload launch
# script.

FROM docker:24-dind

RUN apk upgrade --no-cache && \
    apk add --no-cache bash jq openssh-server openssh-client sshpass \
                       sudo curl shadow procps iproute2

COPY build/roles.json /etc/sysrepair/roles.json
COPY seed.sh /usr/local/sbin/seed.sh

RUN chmod 0600 /etc/sysrepair/roles.json \
 && chmod 0755 /usr/local/sbin/seed.sh \
 && /usr/local/sbin/seed.sh \
 && rm -f /usr/local/sbin/seed.sh

EXPOSE 22 2375 8080

# Inspect AI uses `compose up --wait`, which blocks until this healthcheck
# passes. Without a healthcheck the outer container is considered "running"
# the instant its PID 1 starts — before the inner dockerd socket is ready —
# causing compose exec to fail with "service not running" under load.
HEALTHCHECK --interval=5s --timeout=10s --start-period=15s --retries=18 \
  CMD DOCKER_HOST=unix:///var/run/docker.sock docker info >/dev/null 2>&1

CMD ["/usr/local/sbin/hs-start.sh"]
