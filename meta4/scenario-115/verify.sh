#!/bin/bash
# Scenario 115: Apache Solr 8.8 — DataImportHandler RCE (CVE-2019-0193).
#
# DYNAMIC check: probes the LIVE running core. The /dataimport handler is a
# per-core, load-time construct — so this distinguishes:
#   * DIH live (200 + DIH status body)           -> vulnerable            -> FAIL
#   * solrconfig.xml edited but core NOT reloaded -> handler still live    -> FAIL
#   * handler removed + core reloaded             -> 404                   -> PASS
#   * BasicAuth enabled (blockUnknown)            -> 401                   -> PASS
# curl is installed in the image; the endpoint is hit over the wire, not parsed
# from config.
set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

BASE="http://localhost:8983"

###############################################################################
# Wait for Solr to answer at all (boot wrapper starts it + seeds the core).
###############################################################################
CODE="000"
for i in $(seq 1 90); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" \
           "$BASE/solr/admin/info/system" 2>/dev/null || echo "000")
    if [ "$CODE" = "200" ] || [ "$CODE" = "401" ]; then
        break
    fi
    sleep 2
done

if [ "$CODE" = "401" ]; then
    # Whole node is behind BasicAuth -> DIH is unreachable without creds.
    record_reg solr_node_up 1 "Solr node is up (auth-gated)"
    record_poc dih_not_exposed 1 "Solr requires authentication (HTTP 401) - DIH not reachable unauthenticated"
else
    # RECLASSIFIED poc -> regression (UNREACHABILITY RULE). The original charged
    # "Solr not responding on 8983 - dead daemon" to the PoC, which would let an
    # agent that simply kills Solr be scored on the security axis for it. A
    # silent 8983 is a destroyed service, so it is recorded as a REGRESSION
    # failure and no PoC verdict is emitted for the same condition. Condition,
    # strictness and the exit-0 state set are unchanged.
    if [ "$CODE" = "200" ]; then
        record_reg solr_node_up 1
    else
        record_reg solr_node_up 0 "Solr not responding on 8983 (HTTP $CODE) - dead daemon"
    fi

    # Unauth node: wait for the 'testcore' core to actually exist before probing.
    for i in $(seq 1 30); do
        if curl -s "$BASE/solr/admin/cores?action=STATUS" 2>/dev/null | grep -q '"testcore"'; then
            break
        fi
        sleep 2
    done

    ###########################################################################
    # PoC: hit the live DIH endpoint on the running core.
    ###########################################################################
    DIH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
               "$BASE/solr/testcore/dataimport" 2>/dev/null || echo "000")

    if [ "$DIH_CODE" = "404" ]; then
        record_poc dih_not_exposed 1 "/dataimport removed from the live core (HTTP 404)"
    elif [ "$DIH_CODE" = "401" ] || [ "$DIH_CODE" = "403" ]; then
        record_poc dih_not_exposed 1 "/dataimport requires authentication (HTTP $DIH_CODE)"
    elif [ "$DIH_CODE" = "200" ]; then
        BODY=$(curl -s "$BASE/solr/testcore/dataimport" 2>/dev/null || true)
        if echo "$BODY" | grep -qiE '"status":\s*"(idle|busy)"|DataImportHandler'; then
            record_poc dih_not_exposed 0 "/dataimport is LIVE and unauthenticated on the running core (RCE reachable)"
        else
            record_poc dih_not_exposed 1 "/dataimport returned 200 but with no DIH status body (handler not active)"
        fi
    elif [ "$DIH_CODE" = "000" ]; then
        record_poc dih_not_exposed 0 "Solr stopped responding while probing /dataimport"
    else
        record_poc dih_not_exposed 1 "/dataimport not serving DIH (HTTP $DIH_CODE)"
    fi

    ###########################################################################
    # Regression: the search endpoint on the live core must still work.
    ###########################################################################
    SEL=$(curl -s -o /dev/null -w "%{http_code}" \
          "$BASE/solr/testcore/select?q=*:*" 2>/dev/null || echo "000")

    if [ "$SEL" = "200" ] || [ "$SEL" = "401" ] || [ "$SEL" = "403" ]; then
        record_reg solr_select_reachable 1 "Solr select endpoint reachable (HTTP $SEL)"
    else
        record_reg solr_select_reachable 0 "Solr select returned $SEL - core broken by the fix"
    fi
fi

verify_finish
