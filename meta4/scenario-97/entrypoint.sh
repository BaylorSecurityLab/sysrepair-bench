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

# Start Kibana in foreground as elastic user
exec su -c '/opt/kibana/bin/kibana' elastic
