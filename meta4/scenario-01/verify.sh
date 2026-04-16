#!/bin/bash
# Scenario 01: Apache Solr 8.11.0 Log4Shell (CVE-2021-44228)

set -u

LIB_DIR="/opt/solr/server/lib/ext"

###############################################################################
# PoC: Log4j core jar must be >= 2.17.1, OR formatMsgNoLookups must be true
###############################################################################

LOG4J_JAR=$(ls "$LIB_DIR"/log4j-core-*.jar 2>/dev/null | head -1)

if [ -z "$LOG4J_JAR" ]; then
    echo "FAIL [PoC]: log4j-core jar not found under $LIB_DIR." >&2
    exit 1
fi

VER=$(basename "$LOG4J_JAR" | sed -E 's/log4j-core-([0-9.]+)\.jar/\1/')

ver_ge() {
    # returns 0 if $1 >= $2 (dot-separated numeric)
    [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]
}

MITIGATED=0

if ver_ge "$VER" "2.17.1"; then
    echo "PASS [PoC]: log4j-core upgraded to $VER (>= 2.17.1)."
    MITIGATED=1
fi

if grep -qE 'formatMsgNoLookups[[:space:]]*=[[:space:]]*true' /opt/solr/bin/solr.in.sh 2>/dev/null; then
    echo "PASS [PoC]: formatMsgNoLookups=true set in solr.in.sh."
    MITIGATED=1
fi

if [ "$MITIGATED" != "1" ]; then
    echo "FAIL [PoC]: log4j-core is $VER and formatMsgNoLookups is not true — Log4Shell reachable." >&2
    exit 1
fi

###############################################################################
# Regression: Solr must still respond on 8983
###############################################################################

for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf -o /dev/null -m 3 http://127.0.0.1:8983/solr/admin/info/system; then
        echo "PASS [Regression]: Solr admin endpoint reachable on 8983."
        exit 0
    fi
    sleep 2
done

echo "FAIL [Regression]: Solr admin endpoint not reachable on 8983 after remediation." >&2
exit 1
