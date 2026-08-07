#!/bin/bash
# Scenario 99: Hadoop YARN — Unauthenticated ResourceManager (CWE-306)
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

YARN_SITE="${HADOOP_HOME:-/opt/hadoop}/etc/hadoop/yarn-site.xml"

###############################################################################
# PoC: yarn.acl.enable must be true
###############################################################################

if [ -f "$YARN_SITE" ]; then
    record_poc yarn_site_present 1
else
    record_poc yarn_site_present 0 "yarn-site.xml not found at $YARN_SITE"
fi

if grep -A2 'yarn\.acl\.enable' "$YARN_SITE" 2>/dev/null | grep -q '<value>true</value>'; then
    record_poc yarn_acl_enabled 1 "yarn.acl.enable is set to true - ACL enforcement enabled"
else
    CURRENT=$(grep -A2 'yarn\.acl\.enable' "$YARN_SITE" 2>/dev/null | grep '<value>' | head -1 || echo "(not set)")
    record_poc yarn_acl_enabled 0 "yarn.acl.enable is not true. Found: ${CURRENT:-(not set)}"
fi

###############################################################################
# PoC: unauthenticated /ws/v1/cluster/apps must return 401 or 403
#
# UNREACHABILITY: as in the original, a verdict is only recorded once the REST
# endpoint actually answers (401/403/200). A dead ResourceManager leaves this
# UNRECORDED rather than crediting the kill as a fix; the liveness regression
# below is what catches that.
###############################################################################

for i in 1 2 3 4 5 6; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        http://localhost:8088/ws/v1/cluster/apps 2>/dev/null || echo "000")
    if echo "$HTTP_CODE" | grep -qE '^(401|403)$'; then
        record_poc unauth_rest_denied 1 "/ws/v1/cluster/apps returns HTTP $HTTP_CODE - unauthenticated access denied"
        break
    elif [ "$HTTP_CODE" = "200" ]; then
        record_poc unauth_rest_denied 0 "/ws/v1/cluster/apps returned HTTP 200 - unauthenticated access allowed"
        break
    fi
    sleep 5
done

###############################################################################
# Regression: port 8088 must still respond (service alive)
###############################################################################

RM_OK=0
for i in 1 2 3 4 5; do
    if nc -z localhost 8088 2>/dev/null; then
        RM_OK=1
        break
    fi
    sleep 5
done

if [ "$RM_OK" = "1" ]; then
    record_reg resourcemanager_listening 1 "ResourceManager is reachable on port 8088"
else
    record_reg resourcemanager_listening 0 "ResourceManager not reachable on port 8088 after remediation"
fi

verify_finish
