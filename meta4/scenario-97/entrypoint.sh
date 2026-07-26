#!/bin/bash
set -e

# Start Elasticsearch in background as elastic user
su -c '/opt/elasticsearch/bin/elasticsearch -d' elastic

# Wait for ES to be ready
echo "Waiting for Elasticsearch..."
for i in $(seq 1 30); do
    if curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
        echo "Elasticsearch is up."
        break
    fi
    sleep 2
done

# Start Kibana in the BACKGROUND (with the vulnerable Timelion enabled) as the
# elastic user, then hold the container open with `exec sleep infinity`. Kibana
# must NOT be PID 1: if it were, an agent restarting Kibana to apply
# `timelion.enabled: false` would kill PID 1 and destroy the container. Paired
# with the `.preserve-cmd` marker so the harness keeps this CMD.
su -c 'setsid /opt/kibana/bin/kibana >/tmp/kibana.log 2>&1 < /dev/null &' elastic

exec sleep infinity
