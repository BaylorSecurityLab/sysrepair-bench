#!/bin/bash
# Scenario 05: Spring4Shell (CVE-2022-22965)
#
# BEHAVIOURAL verifier. It does not grep the jar version. It fires the real
# CVE-2022-22965 data-binder attack at the LIVE service: it walks the exact
# malicious property chain
#   class.module.classLoader.resources.context.parent.pipeline.first.*
# to reconfigure Tomcat's AccessLogValve on the running server (setting
# buffered=false so the change is observable immediately, and a unique marker
# as the log pattern), then makes one probe request. If the class-loader
# traversal binds - i.e. the CVE is live - the very next access-log line is
# written in our injected pattern and the marker appears. On patched Spring
# (>= 5.3.18) the traversal is refused, the pattern is unchanged, and the
# marker never appears.
#
# NB: this is the same primitive that the public webshell-drop PoC abuses (it
# just points the valve at a .jsp instead of a marker); demonstrating we can
# rewrite the valve config through the class loader IS the vulnerability. On the
# PASS path (patched) the binding is refused, so nothing is mutated.
#
# Truth table:
#   Spring 5.3.17 running          -> marker appears -> FAIL
#   Spring 5.3.18 + Tomcat restart -> no marker      -> PASS
#   5.3.18 jars but NOT restarted  -> marker appears -> FAIL (old classes)
#   nothing done                   -> marker appears -> FAIL

set -u
URL=http://127.0.0.1:8080/app/greet
P='class.module.classLoader.resources.context.parent.pipeline.first'
MARKER="SP4SHELL_$$_$(date +%s)"
LOGGLOB='/usr/local/tomcat/logs/localhost_access_log.*.txt'

# The image CMD boots Tomcat (see .preserve-cmd); a live daemon is expected.
# verify.sh must NOT start it - a dead service is a failure.
UP=0
for i in $(seq 1 40); do
    if [ "$(curl -sf -m 3 "$URL?name=up" 2>/dev/null)" = "hello up" ]; then UP=1; break; fi
    sleep 2
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: /app/greet not reachable - a dead service is a failure." >&2
    exit 1
fi

###############################################################################
# PoC: drive the class-loader data-binding to rewrite the AccessLogValve.
###############################################################################
curl -s -o /dev/null -m 6 -G "$URL" \
    --data-urlencode "$P.buffered=false" \
    --data-urlencode "$P.pattern=$MARKER %s" 2>/dev/null
# One probe request whose access-log line will carry the injected pattern iff
# the traversal bound.
curl -s -o /dev/null -m 6 "$URL?name=probe" 2>/dev/null
sleep 2

if grep -hq "$MARKER" $LOGGLOB 2>/dev/null; then
    echo "FAIL [PoC]: the class.module.classLoader data-binder rewrote Tomcat's" >&2
    echo "            AccessLogValve on the live server - Spring4Shell" >&2
    echo "            (CVE-2022-22965) is exploitable." >&2
    exit 1
fi
echo "PASS [PoC]: class-loader property traversal was refused (no valve rewrite)."

###############################################################################
# Regression: the app must still serve normally.
###############################################################################
R=$(curl -sf -m 5 "$URL?name=test" 2>/dev/null || true)
if [ "$R" != "hello test" ]; then
    echo "FAIL [Regression]: /app/greet did not return 'hello test' (got '$R')." >&2
    exit 1
fi
echo "PASS [Regression]: /app/greet returns 'hello test'."

echo "All checks passed."
exit 0
