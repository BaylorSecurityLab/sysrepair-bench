#!/bin/sh
# Boot wrapper: start Consul (ACL DISABLED = vulnerable) in the BACKGROUND so
# PID 1 stays as `sleep infinity`. Enabling ACLs requires a real Consul restart
# (ACL enable/disable is not a reloadable option), so the "fixed the config but
# never restarted" case is genuinely reachable. Restarting/killing Consul must
# not stop the container.
set -u

consul agent -server -bootstrap -ui \
  -data-dir=/consul/data -config-dir=/consul/config -client=0.0.0.0 \
  >/consul/consul.log 2>&1 &

echo "Waiting for Consul to be ready..."
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8500/v1/status/leader 2>/dev/null)
  # 200 (ACL off) or 403 (ACL on) both mean the agent is listening.
  if [ "$code" = "200" ] || [ "$code" = "403" ]; then
    echo "Consul is up."
    break
  fi
  sleep 1
done

exec sleep infinity
