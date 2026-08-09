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
#
# Two-component protocol: every check runs and is recorded with its kind, so
# "no marker because Tomcat was killed" is reported as regression_pass=false
# rather than collapsing into a bare exit 1. See lib/verifylib.sh.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

URL=http://127.0.0.1:8080/app/greet
P='class.module.classLoader.resources.context.parent.pipeline.first'
MARKER="SP4SHELL_$$_$(date +%s)"
LOGGLOB='/usr/local/tomcat/logs/localhost_access_log.*.txt'

# The image CMD boots Tomcat (see .preserve-cmd); a live daemon is expected.
# verify.sh must NOT start it - a dead service is a failure. Reachability is a
# REGRESSION check: it is what separates "patched Spring" from "patched Spring
# and destroyed Tomcat". It does not abort the run.
UP=0
for i in $(seq 1 40); do
    if [ "$(curl -sf -m 3 "$URL?name=up" 2>/dev/null)" = "hello up" ]; then UP=1; break; fi
    sleep 2
done
if [ "$UP" = "1" ]; then
    record_reg app_greet_reachable 1
else
    record_reg app_greet_reachable 0 "/app/greet not reachable - a dead service is a failure"
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
    record_poc classloader_traversal_refused 0 "the class.module.classLoader data-binder rewrote Tomcat's AccessLogValve on the live server - Spring4Shell (CVE-2022-22965) is exploitable"
else
    record_poc classloader_traversal_refused 1
fi

###############################################################################
# Regression: the app must still serve normally.
###############################################################################
R=$(curl -sf -m 5 "$URL?name=test" 2>/dev/null || true)
if [ "$R" = "hello test" ]; then
    record_reg app_greet_serves 1
else
    record_reg app_greet_serves 0 "/app/greet did not return 'hello test' (got '$R')"
fi

verify_finish
