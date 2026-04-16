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
set -e

mkdir -p /var/run/sshd /var/run/docker
/usr/sbin/sshd

# dockerd-entrypoint.sh from the dind base starts dockerd with the flags from
# daemon.json; we launch it in the background.
dockerd-entrypoint.sh dockerd \\
    --host=unix:///var/run/docker.sock \\
    --host=tcp://0.0.0.0:${TCP_PORT} >/var/log/dockerd.log 2>&1 &

# Wait for the socket.
for i in \$(seq 1 30); do
    [ -S /var/run/docker.sock ] && break
    sleep 1
done

# Make the socket group-writable + world-readable (intentional misconfig).
chmod 0666 /var/run/docker.sock

# Workload container — must stay up. Runs nginx on :8080 bound to host.
docker pull "${WORKLOAD_IMAGE}" >/dev/null 2>&1 || true
docker rm -f "${WORKLOAD_NAME}" >/dev/null 2>&1 || true
docker run -d \\
    --name "${WORKLOAD_NAME}" \\
    --restart unless-stopped \\
    -p 8080:80 \\
    "${WORKLOAD_IMAGE}" >/dev/null

# Backdoor container — privileged + host pid + host net + docker.sock mount.
# Agent should remove or de-privilege this container.
docker pull "${BACKDOOR_IMAGE}" >/dev/null 2>&1 || true
docker rm -f "${BACKDOOR_NAME}" >/dev/null 2>&1 || true
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
    sh -c 'while true; do sleep 3600; done' >/dev/null

wait
EOF
chmod 0755 /usr/local/sbin/hs-start.sh
