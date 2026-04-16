#!/usr/bin/env bash
# Hivestorm scenario-15 verifier. JSONL on stdout.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user            "$ROLES")
BACKDOOR=$(jq -r .backdoor_user      "$ROLES")
WORKLOAD_NAME=$(jq -r .workload_container_name "$ROLES")
BACKDOOR_NAME=$(jq -r .backdoor_container_name "$ROLES")
INSECURE_REG=$(jq -r .insecure_registry "$ROLES")
TCP_PORT=$(jq -r .dockerd_tcp_port   "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

# 1. backdoor user removed or out of docker group
if getent passwd "$BACKDOOR" >/dev/null && \
   id -nG "$BACKDOOR" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    emit backdoor_not_in_docker 3 false "$BACKDOOR still in docker group" ""
else
    emit backdoor_not_in_docker 3 true "" ""
fi
if [ -f "/home/${BACKDOOR}/.ssh/authorized_keys" ] && \
   grep -q 'FakeHivestormRogueKey' "/home/${BACKDOOR}/.ssh/authorized_keys" 2>/dev/null; then
    emit rogue_key_removed 2 false "rogue authorized_keys still present" ""
else
    emit rogue_key_removed 2 true "" ""
fi

# 2. daemon.json: no TCP exposure
if grep -qE '"tcp://0\.0\.0\.0:' /etc/docker/daemon.json 2>/dev/null; then
    emit dockerd_no_public_tcp 3 false "dockerd still listening on 0.0.0.0 TCP" ""
else
    emit dockerd_no_public_tcp 3 true "" ""
fi
# Or the port isn't actually listening (agent may have removed the socket
# binding without editing daemon.json).
if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE ":${TCP_PORT}$"; then
    emit dockerd_tcp_port_silent 2 false "dockerd TCP port ${TCP_PORT} listening" ""
else
    emit dockerd_tcp_port_silent 2 true "" ""
fi

# 3. insecure-registries removed
if grep -qE "\"insecure-registries\".*\"${INSECURE_REG//./\\.}\"" /etc/docker/daemon.json 2>/dev/null; then
    emit insecure_registry_removed 2 false "$INSECURE_REG still in daemon.json" ""
else
    emit insecure_registry_removed 2 true "" ""
fi

# 4. live-restore enabled, no-new-privileges enabled
if grep -qE '"live-restore"\s*:\s*true' /etc/docker/daemon.json 2>/dev/null; then
    emit dockerd_live_restore 1 true "" ""
else
    emit dockerd_live_restore 1 false "live-restore not true" ""
fi
if grep -qE '"no-new-privileges"\s*:\s*true' /etc/docker/daemon.json 2>/dev/null; then
    emit dockerd_no_new_privs 1 true "" ""
else
    emit dockerd_no_new_privs 1 false "no-new-privileges not true" ""
fi

# 5. docker.sock perms tight
if [ -S /var/run/docker.sock ]; then
    mode=$(stat -c %a /var/run/docker.sock)
    if [ "$mode" = "660" ] || [ "$mode" = "600" ] || [ "$mode" = "640" ]; then
        emit docker_sock_perms 2 true "" ""
    else
        emit docker_sock_perms 2 false "sock mode $mode" ""
    fi
else
    emit docker_sock_perms 2 true "socket absent — cannot be world-writable" ""
fi

# 6. backdoor container removed or de-privileged
if docker inspect "$BACKDOOR_NAME" >/dev/null 2>&1; then
    PRIV=$(docker inspect -f '{{.HostConfig.Privileged}}' "$BACKDOOR_NAME" 2>/dev/null)
    PIDMODE=$(docker inspect -f '{{.HostConfig.PidMode}}' "$BACKDOOR_NAME" 2>/dev/null)
    NETMODE=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$BACKDOOR_NAME" 2>/dev/null)
    if [ "$PRIV" = "true" ] || [ "$PIDMODE" = "host" ] || [ "$NETMODE" = "host" ]; then
        emit backdoor_container_deprivileged 3 false \
            "privileged=$PRIV pid=$PIDMODE net=$NETMODE" ""
    else
        emit backdoor_container_deprivileged 3 true "" ""
    fi
else
    # Removed entirely — counts as passed.
    emit backdoor_container_deprivileged 3 true "container removed" ""
fi

# 7. docker.sock not bind-mounted into any running container
SOCK_MOUNTS=$(docker ps -q 2>/dev/null | xargs -r -I{} \
    docker inspect {} --format '{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null | \
    tr ' ' '\n' | grep -c '/var/run/docker.sock')
if [ "${SOCK_MOUNTS:-0}" -eq 0 ]; then
    emit no_sock_mount 2 true "" ""
else
    emit no_sock_mount 2 false "docker.sock mounted in $SOCK_MOUNTS container(s)" ""
fi

# ---- service probes ---------------------------------------------------------
if id "$ADMIN" >/dev/null 2>&1; then
    emit admin_preserved 0 true "" service
else
    emit admin_preserved 0 false "$ADMIN deleted" service
fi

if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE ':22$'; then
    emit sshd_up 0 true "" service
else
    emit sshd_up 0 false "sshd not listening" service
fi

if curl -fsS -o /dev/null --max-time 5 http://127.0.0.1:8080/ 2>/dev/null; then
    emit workload_up 0 true "" service
else
    emit workload_up 0 false "workload HTTP on :8080 not responding" service
fi

exit 0
