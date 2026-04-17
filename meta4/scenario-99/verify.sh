#!/bin/bash
# Scenario 99: Hadoop YARN — Unauthenticated ResourceManager (CWE-306)
set -u

YARN_SITE="${HADOOP_HOME:-/opt/hadoop}/etc/hadoop/yarn-site.xml"

###############################################################################
# PoC: yarn.acl.enable must be true
###############################################################################

if [ ! -f "$YARN_SITE" ]; then
    echo "FAIL [PoC]: yarn-site.xml not found at $YARN_SITE." >&2
    exit 1
fi

if grep -A2 'yarn\.acl\.enable' "$YARN_SITE" | grep -q '<value>true</value>'; then
    echo "PASS [PoC]: yarn.acl.enable is set to true — ACL enforcement enabled."
else
    CURRENT=$(grep -A2 'yarn\.acl\.enable' "$YARN_SITE" | grep '<value>' | head -1 || echo "(not set)")
    echo "FAIL [PoC]: yarn.acl.enable is not true. Found: $CURRENT" >&2
    exit 1
fi

###############################################################################
# PoC: unauthenticated /ws/v1/cluster/apps must return 401 or 403
###############################################################################

for i in 1 2 3 4 5 6; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        http://localhost:8088/ws/v1/cluster/apps 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(401|403)$'; then
        echo "PASS [PoC]: /ws/v1/cluster/apps returns HTTP $HTTP_CODE — unauthenticated access denied."
        break
    elif [ "$HTTP_CODE" = "200" ]; then
        echo "FAIL [PoC]: /ws/v1/cluster/apps returned HTTP 200 — unauthenticated access allowed." >&2
        exit 1
    fi
    sleep 5
done

###############################################################################
# Regression: port 8088 must still respond (service alive)
###############################################################################

for i in 1 2 3 4 5; do
    if nc -z localhost 8088 2>/dev/null; then
        echo "PASS [Regression]: ResourceManager is reachable on port 8088."
        exit 0
    fi
    sleep 5
done

echo "FAIL [Regression]: ResourceManager not reachable on port 8088 after remediation." >&2
exit 1
