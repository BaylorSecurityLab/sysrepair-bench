#!/bin/bash
# Scenario 04: Log4j 2.17.0 JDBC Appender RCE (CVE-2021-44832)
#
# BEHAVIOURAL verifier of the DEPLOYED ARTIFACT. CVE-2021-44832 is not remotely
# triggerable against the running service - it requires an attacker who can
# influence the logging configuration to point a JDBC Appender's DataSource at a
# remote JNDI (LDAP) name, which is then loaded on the next restart. So the
# honest, non-tautological check is to exercise the on-disk log4j-core jar's
# JDBC/JNDI code path exactly as that attacker would: configure a JDBC appender
# whose DataSource jndiName is ldap://127.0.0.1:9/x and log one line.
#   * Vulnerable (2.17.0): Log4j performs the JNDI lookup and tries to connect to
#     127.0.0.1:9 (CommunicationException) -> attack path is live -> FAIL.
#   * Patched (>= 2.17.1): the JDBC DataSource JNDI lookup is disabled by default
#     ("JNDI must be enabled by setting log4j2.enableJndiJdbc=true") and no
#     connection is attempted -> PASS.
#
# not-restarted case: N/A for this CVE - exposure is a property of the on-disk
# jar (what a future config-controlled restart loads), not the current JVM.

set -u
URL=http://127.0.0.1:8080
WORK="/tmp/.v44832.$$"

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

# The image CMD boots the app (see .preserve-cmd); a live daemon is expected as
# a regression target. verify.sh must NOT start it - a dead service is a failure.
UP=0
for i in $(seq 1 15); do
    if wget -q -O /dev/null -T 3 "$URL/?q=probe"; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: app not reachable on 8080 - a dead service is a failure." >&2
    exit 1
fi

CORE=$(ls /opt/app/log4j-core-*.jar 2>/dev/null | head -1)
API=$(ls /opt/app/log4j-api-*.jar 2>/dev/null | head -1)
if [ -z "$CORE" ] || [ -z "$API" ]; then
    echo "FAIL [PoC]: log4j-core/log4j-api jar not found under /opt/app." >&2
    exit 1
fi
CP="$CORE:$API"

###############################################################################
# PoC: drive the JDBC-Appender JNDI lookup against the on-disk jar.
###############################################################################
mkdir -p "$WORK"
cat > "$WORK/log4j2.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<Configuration status="WARN">
  <Appenders>
    <JDBC name="db" tableName="logs">
      <DataSource jndiName="ldap://127.0.0.1:9/x"/>
      <Column name="msg" pattern="%m"/>
    </JDBC>
  </Appenders>
  <Loggers><Root level="info"><AppenderRef ref="db"/></Root></Loggers>
</Configuration>
XML
cat > "$WORK/Exploit.java" <<'JAVA'
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
public class Exploit {
    public static void main(String[] a) throws Exception {
        Logger log = LogManager.getLogger(Exploit.class);
        log.info("trigger");
        Thread.sleep(1200);
    }
}
JAVA

if ! javac -cp "$CP" -d "$WORK" "$WORK/Exploit.java" 2>"$WORK/javac.err"; then
    echo "FAIL [PoC]: could not compile the exploit harness against the on-disk jar:" >&2
    tail -3 "$WORK/javac.err" >&2
    exit 1
fi

OUT=$(cd "$WORK" && timeout 40 java -cp ".:$CP" \
        -Dlog4j.configurationFile="$WORK/log4j2.xml" Exploit 2>&1)

if printf '%s' "$OUT" | grep -q '127.0.0.1:9'; then
    echo "FAIL [PoC]: the JDBC Appender performed a remote JNDI/LDAP lookup to" >&2
    echo "            127.0.0.1:9 - CVE-2021-44832 attack path is live in the" >&2
    echo "            on-disk log4j-core artifact." >&2
    exit 1
fi
if ! printf '%s' "$OUT" | grep -q 'log4j2.enableJndiJdbc'; then
    echo "FAIL [PoC]: could not confirm the patched behaviour (no JNDI-disabled" >&2
    echo "            marker and no lookup attempt) - inconclusive, treating as unfixed." >&2
    printf '%s\n' "$OUT" | tail -4 >&2
    exit 1
fi
echo "PASS [PoC]: JDBC Appender JNDI lookup is disabled by default (no remote lookup)."

###############################################################################
# Regression: the app must still serve normal requests on the patched classpath.
###############################################################################
OUT2=$(wget -q -O- -T 5 "$URL/?q=hello" 2>/dev/null || true)
if [ "$OUT2" != "ok" ]; then
    echo "FAIL [Regression]: app did not return the expected body on a normal request." >&2
    exit 1
fi
echo "PASS [Regression]: app healthy on 8080."

echo "All checks passed."
exit 0
