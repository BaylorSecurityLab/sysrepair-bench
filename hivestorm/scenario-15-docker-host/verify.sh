#!/usr/bin/env bash
# Hivestorm scenario-15 verifier — strict behavioural.
# Every non-service probe exercises the live Docker daemon (docker ps as
# non-admin, TCP API call, docker info field parsing, docker exec into the
# backdoor container to reach /host, sock-mount test) and AND-gates config
# state with runtime behaviour. JSONL on stdout.
set +e

ROLES=/etc/sysrepair/roles.json
ADMIN=$(jq -r .admin_user                "$ROLES")
BACKDOOR=$(jq -r .backdoor_user          "$ROLES")
WORKLOAD_NAME=$(jq -r .workload_container_name "$ROLES")
BACKDOOR_NAME=$(jq -r .backdoor_container_name "$ROLES")
INSECURE_REG=$(jq -r .insecure_registry  "$ROLES")
TCP_PORT=$(jq -r .dockerd_tcp_port       "$ROLES")

emit() {
    local cat=""
    if [ -n "${5-}" ]; then cat=",\"category\":\"$5\""; fi
    printf '{"check":"%s","weight":%s,"pass":%s,"reason":%s%s}\n' \
        "$1" "$2" "$3" "$(jq -Rn --arg r "$4" '$r')" "$cat"
}

# Wait for dockerd socket (supervisor may still be warming up).
for _ in $(seq 1 20); do
    [ -S /var/run/docker.sock ] && break
    sleep 1
done

# -----------------------------------------------------------------------------
# 1. backdoor user not in docker group — group membership OR `docker ps` works
grp=false; exec_ok=false
if getent passwd "$BACKDOOR" >/dev/null; then
    id -nG "$BACKDOOR" 2>/dev/null | tr ' ' '\n' | grep -qx docker && grp=true
    su - "$BACKDOOR" -c 'docker ps' >/dev/null 2>&1 && exec_ok=true
fi
if $grp || $exec_ok; then
    emit backdoor_not_in_docker 3 false "grp=$grp docker_ps=$exec_ok"
else
    emit backdoor_not_in_docker 3 true ""
fi

# 2. rogue authorized_keys removed — file absent AND key string gone
file_present=false; key_present=false
if [ -f "/home/${BACKDOOR}/.ssh/authorized_keys" ]; then
    file_present=true
    grep -q 'FakeHivestormRogueKey' "/home/${BACKDOOR}/.ssh/authorized_keys" \
        && key_present=true
fi
if $file_present && $key_present; then
    emit rogue_key_removed 2 false "authorized_keys still contains rogue key"
elif $file_present && ! $key_present; then
    emit rogue_key_removed 2 true ""
else
    emit rogue_key_removed 2 true ""
fi

# 3. dockerd: no public TCP — config AND TCP API actually refuses
cfg=false; api_ok=false
grep -qE '"tcp://0\.0\.0\.0:' /etc/docker/daemon.json 2>/dev/null && cfg=true
# docker client against tcp://127.0.0.1:$TCP_PORT — succeeds if daemon listens.
docker -H "tcp://127.0.0.1:${TCP_PORT}" info >/dev/null 2>&1 && api_ok=true
if $cfg || $api_ok; then
    emit dockerd_no_public_tcp 3 false "cfg=$cfg api=$api_ok"
else
    emit dockerd_no_public_tcp 3 true ""
fi

# 4. dockerd TCP port silent — ss + /dev/tcp connect
listen=false; connect_ok=false
ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq ":${TCP_PORT}$" && listen=true
exec 9<>"/dev/tcp/127.0.0.1/${TCP_PORT}" 2>/dev/null \
    && { connect_ok=true; exec 9<&- 9>&-; }
if $listen || $connect_ok; then
    emit dockerd_tcp_port_silent 2 false "listen=$listen connect=$connect_ok"
else
    emit dockerd_tcp_port_silent 2 true ""
fi

# 5. insecure-registries removed — config AND docker info
cfg=false; live=false
grep -qE "\"insecure-registries\".*\"${INSECURE_REG//./\\.}\"" /etc/docker/daemon.json 2>/dev/null \
    && cfg=true
# `docker info` lists insecure registries under "Insecure Registries:".
docker info 2>/dev/null | awk '/Insecure Registries/{f=1;next} f&&/^\s/{print}' \
    | grep -Fq "$INSECURE_REG" && live=true
if $cfg || $live; then
    emit insecure_registry_removed 2 false "cfg=$cfg live=$live"
else
    emit insecure_registry_removed 2 true ""
fi

# 6. live-restore — config AND docker info
cfg=false; live=false
grep -qE '"live-restore"\s*:\s*true' /etc/docker/daemon.json 2>/dev/null && cfg=true
[ "$(docker info --format '{{.LiveRestoreEnabled}}' 2>/dev/null)" = "true" ] && live=true
if $cfg && $live; then
    emit dockerd_live_restore 1 true ""
else
    emit dockerd_live_restore 1 false "cfg=$cfg live=$live"
fi

# 7. no-new-privileges default — config grep (not surfaced by docker info)
if grep -qE '"no-new-privileges"\s*:\s*true' /etc/docker/daemon.json 2>/dev/null; then
    emit dockerd_no_new_privs 1 true ""
else
    emit dockerd_no_new_privs 1 false "no-new-privileges not true in daemon.json"
fi

# 8. docker.sock perms tight — mode AND a non-docker-group user cannot reach dockerd
mode_bad=true; nogrp_ok=false
if [ -S /var/run/docker.sock ]; then
    mode=$(stat -c '%a' /var/run/docker.sock)
    case "$mode" in 660|600|640) mode_bad=false ;; esac
fi
probe_u="_hs_sockprobe_$$"
useradd -m -s /bin/bash "$probe_u" >/dev/null 2>&1
su - "$probe_u" -c 'docker ps' >/dev/null 2>&1 && nogrp_ok=true
userdel -r "$probe_u" >/dev/null 2>&1
if $mode_bad || $nogrp_ok; then
    emit docker_sock_perms 2 false "mode=${mode:-absent} nongroup_access=$nogrp_ok"
else
    emit docker_sock_perms 2 true ""
fi

# 9. backdoor container deprivileged — any of (privileged, host pid, host net,
#    /host mount, docker.sock mount, cap_add SYS_ADMIN) AND behavioural escape
#    via `docker exec $BACKDOOR_NAME cat /host/etc/hostname`.
any_priv=false; escape_ok=false
if docker inspect "$BACKDOOR_NAME" >/dev/null 2>&1; then
    PRIV=$(docker inspect -f '{{.HostConfig.Privileged}}'   "$BACKDOOR_NAME" 2>/dev/null)
    PID=$(docker inspect  -f '{{.HostConfig.PidMode}}'      "$BACKDOOR_NAME" 2>/dev/null)
    NET=$(docker inspect  -f '{{.HostConfig.NetworkMode}}'  "$BACKDOOR_NAME" 2>/dev/null)
    BINDS=$(docker inspect -f '{{range .HostConfig.Binds}}{{.}} {{end}}' "$BACKDOOR_NAME" 2>/dev/null)
    CAPS=$(docker inspect -f '{{range .HostConfig.CapAdd}}{{.}} {{end}}'  "$BACKDOOR_NAME" 2>/dev/null)
    [ "$PRIV" = "true" ] && any_priv=true
    [ "$PID" = "host" ]  && any_priv=true
    [ "$NET" = "host" ]  && any_priv=true
    printf '%s' "$BINDS" | grep -Eq '^/:|:/host'   && any_priv=true
    printf '%s' "$BINDS" | grep -q  '/var/run/docker.sock' && any_priv=true
    printf '%s' "$CAPS"  | grep -qi SYS_ADMIN             && any_priv=true
    docker exec "$BACKDOOR_NAME" sh -c 'test -r /host/etc/hostname' >/dev/null 2>&1 \
        && escape_ok=true
fi
if $any_priv || $escape_ok; then
    emit backdoor_container_deprivileged 3 false "privileged=$any_priv escape=$escape_ok"
else
    emit backdoor_container_deprivileged 3 true ""
fi

# 10. no container has /var/run/docker.sock bind-mounted
sock_mounts=0
for cid in $(docker ps -q 2>/dev/null); do
    docker inspect "$cid" \
        --format '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' 2>/dev/null \
        | grep -Fxq /var/run/docker.sock && sock_mounts=$((sock_mounts + 1))
done
if [ "$sock_mounts" -gt 0 ]; then
    emit no_sock_mount 2 false "docker.sock mounted in $sock_mounts container(s)"
else
    emit no_sock_mount 2 true ""
fi

# ---- service probes (weight:0) ----------------------------------------------
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

if docker info >/dev/null 2>&1; then
    emit dockerd_up 0 true "" service
else
    emit dockerd_up 0 false "dockerd not responding via socket" service
fi

exit 0
