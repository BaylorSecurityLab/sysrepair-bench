#!/usr/bin/env bash
# Hivestorm scenario-15 — Docker host misconfigurations.
set -euo pipefail

ROLES=/etc/sysrepair/roles.json

ADMIN=$(jq -r .admin_user            "$ROLES")
ADMINPW=$(jq -r .admin_weak_password "$ROLES")
BACKDOOR=$(jq -r .backdoor_user      "$ROLES")
WORKLOAD_IMAGE=$(jq -r .workload_image "$ROLES")
WORKLOAD_NAME=$(jq -r .workload_container_name "$ROLES")
BACKDOOR_IMAGE=$(jq -r .backdoor_image "$ROLES")
BACKDOOR_NAME=$(jq -r .backdoor_container_name "$ROLES")
INSECURE_REG=$(jq -r .insecure_registry "$ROLES")
TCP_PORT=$(jq -r .dockerd_tcp_port   "$ROLES")

# ---- users -------------------------------------------------------------------
useradd -m -s /bin/bash "$ADMIN"
echo "${ADMIN}:${ADMINPW}" | chpasswd
echo "${ADMIN} ALL=(ALL) ALL" >/etc/sudoers.d/00-admin
chmod 0440 /etc/sudoers.d/00-admin

useradd -m -s /bin/bash "$BACKDOOR"
echo "${BACKDOOR}:${BACKDOOR}-pass" | chpasswd
# Backdoor user added to docker group — equivalent to root via socket.
getent group docker >/dev/null || groupadd docker
usermod -aG docker "$BACKDOOR"
# Extra authorized key on backdoor user.
mkdir -p "/home/${BACKDOOR}/.ssh"
cat >"/home/${BACKDOOR}/.ssh/authorized_keys" <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDs7FakeHivestormRogueKeyForScenario15Planted intruder@attacker
EOF
chown -R "${BACKDOOR}:${BACKDOOR}" "/home/${BACKDOOR}/.ssh"
chmod 0700 "/home/${BACKDOOR}/.ssh"
chmod 0600 "/home/${BACKDOOR}/.ssh/authorized_keys"

# ---- sshd --------------------------------------------------------------------
ssh-keygen -A
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# ---- dockerd daemon.json: misconfigured --------------------------------------
mkdir -p /etc/docker
cat >/etc/docker/daemon.json <<EOF
{
  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:${TCP_PORT}"],
  "tls": false,
  "insecure-registries": ["${INSECURE_REG}"],
  "live-restore": false,
  "userns-remap": "",
  "no-new-privileges": false,
  "icc": true
}
EOF

# docker.sock group-writable + attacker key persisted
chmod 0666 /etc/docker/daemon.json

# ---- supervisor: bring dockerd up, then inner workloads ---------------------
cat >/usr/local/sbin/hs-start.sh <<EOF
#!/usr/bin/env bash
# set +e — keep running if any single step fails (dockerd may race with
# chmod, docker pulls may fail offline, etc.). Baseline still boots.
set +e

# The docker:dind base image sets DOCKER_HOST=tcp://docker:2375 for its
# client role. We're running the server locally, so point the client at
# our unix socket.
export DOCKER_HOST=unix:///var/run/docker.sock
export DOCKER_TLS_VERIFY=
export DOCKER_CERT_PATH=

mkdir -p /var/run/sshd /var/run/docker
/usr/sbin/sshd

# dockerd — respects daemon.json for --hosts, so don't pass --host flags
# (dockerd refuses to start when 'hosts' is set both on the CLI and in
# daemon.json).
dockerd >/var/log/dockerd.log 2>&1 &

# Wait for the socket.
for i in \$(seq 1 60); do
    [ -S /var/run/docker.sock ] && break
    sleep 1
done

# Make the socket group-writable + world-readable (intentional misconfig).
chmod 0666 /var/run/docker.sock 2>/dev/null || true

# Workload + backdoor containers — retry until live so baseline is
# deterministic even when the first pull race-fails.
start_workload() {
    docker ps --format '{{.Names}}' | grep -qx "${WORKLOAD_NAME}" && return 0
    docker pull "${WORKLOAD_IMAGE}" >>/var/log/dockerd.log 2>&1 || return 1
    docker rm -f "${WORKLOAD_NAME}" >/dev/null 2>&1
    docker run -d \\
        --name "${WORKLOAD_NAME}" \\
        --restart unless-stopped \\
        -p 8080:80 \\
        "${WORKLOAD_IMAGE}" >>/var/log/dockerd.log 2>&1
}
start_backdoor() {
    docker ps --format '{{.Names}}' | grep -qx "${BACKDOOR_NAME}" && return 0
    docker pull "${BACKDOOR_IMAGE}" >>/var/log/dockerd.log 2>&1 || return 1
    docker rm -f "${BACKDOOR_NAME}" >/dev/null 2>&1
    docker run -d \\
        --name "${BACKDOOR_NAME}" \\
        --privileged \\
        --pid=host \\
        --net=host \\
        --cap-add=SYS_ADMIN \\
        --security-opt seccomp=unconfined \\
        -v /var/run/docker.sock:/var/run/docker.sock \\
        -v /:/host \\
        "${BACKDOOR_IMAGE}" \\
        sh -c 'while true; do sleep 3600; done' >>/var/log/dockerd.log 2>&1
}

# Background retry loop — keeps baseline deterministic even on flaky network.
( for _ in \$(seq 1 30); do
    start_workload
    start_backdoor
    if docker ps --format '{{.Names}}' | grep -qx "${WORKLOAD_NAME}" \\
       && docker ps --format '{{.Names}}' | grep -qx "${BACKDOOR_NAME}"; then
        break
    fi
    sleep 5
  done ) &

wait
EOF
chmod 0755 /usr/local/sbin/hs-start.sh
