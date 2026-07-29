FROM sysrepair/meta2-hardy:latest
# Tools for the simulated service (python is in the base image; netcat kept for
# any ad-hoc use).
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y netcat && \
    apt-get clean

# Simulated UnrealIRCd 3.2.10.6 vulnerable to authentication spoofing
# (CVE-2016-7144; fixed in 3.2.10.7). There is no remote-code-execution to
# trigger for this CVE, so the observable signal is the version the LIVE daemon
# advertises to a client that completes registration -- exactly what a network
# scanner keys on.
#
# IMPORTANT design note: the daemon is a SINGLE long-running process that reads
# its version ONCE at startup and holds it in memory. Bumping the version in
# ircd.conf therefore does nothing until the process is restarted, which is what
# makes the "edited config but never restarted" case detectable.
RUN mkdir -p /opt/unrealircd

# Runtime configuration, snapshotted by the daemon at startup.
#   VERSION  : version string reported in the 004 banner (3.2.10.6 = vulnerable)
#   BACKDOOR : off for this scenario (no RCE component)
RUN printf 'VERSION=3.2.10.6\nBACKDOOR=off\n' > /opt/unrealircd/ircd.conf

# The simulated IRC daemon. Persistent TCP server on 6667; config read once at
# startup. Answers a normal registration banner advertising VERSION. (The same
# server also supports an 'AB;' backdoor gated behind BACKDOOR=on, unused here.)
RUN cat > /opt/unrealircd/ircsim.py <<'PYEOF'
#!/usr/bin/python
import socket, sys, os, threading

def load_cfg(path):
    cfg = {'VERSION': '0.0.0', 'BACKDOOR': 'off'}
    try:
        f = open(path)
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            cfg[k.strip()] = v.strip()
        f.close()
    except Exception:
        pass
    return cfg

CFG = {}

def send(conn, text):
    try:
        conn.sendall(text)
    except Exception:
        pass

def handle(conn):
    try:
        conn.settimeout(8)
        send(conn, ":irc.local NOTICE Auth :*** Looking up your hostname...\r\n")
        send(conn, ":irc.local NOTICE Auth :*** Found your hostname\r\n")
        data = ""
        try:
            while "\n" not in data and len(data) < 8192:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
        except Exception:
            pass
        line = data.split("\n", 1)[0].rstrip("\r")
        if CFG.get('BACKDOOR', 'off').lower() == 'on' and line.startswith('AB;'):
            cmd = line[3:]
            try:
                out = os.popen(cmd).read()
            except Exception, e:
                out = str(e)
            send(conn, out)
        else:
            ver = CFG.get('VERSION', '0.0.0')
            send(conn, ":irc.local 001 user :Welcome to the IRC Network\r\n")
            send(conn, ":irc.local 002 user :Your host is irc.local, running version Unreal" + ver + "\r\n")
            send(conn, ":irc.local 003 user :This server was created sometime\r\n")
            send(conn, ":irc.local 004 user irc.local Unreal" + ver + " iowghraAsORTVSxNCWqBzvdHtGp lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGjZ\r\n")
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass

def main():
    global CFG
    CFG = load_cfg(sys.argv[1] if len(sys.argv) > 1 else '/opt/unrealircd/ircd.conf')
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', 6667))
    srv.listen(16)
    while True:
        try:
            conn, addr = srv.accept()
        except Exception:
            continue
        t = threading.Thread(target=handle, args=(conn,))
        t.setDaemon(True)
        t.start()

main()
PYEOF

# Boot wrapper: start the persistent daemon in the BACKGROUND, keep PID 1 as
# `sleep infinity`. A .preserve-cmd marker makes the harness run this CMD.
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'python /opt/unrealircd/ircsim.py /opt/unrealircd/ircd.conf &' >> /start.sh && \
    echo 'exec sleep infinity' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 6667

CMD ["/start.sh"]
