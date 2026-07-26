FROM --platform=linux/amd64 debian:bookworm-slim

# Zabbix 5.0 — Default Credentials + API RCE (CVE-2022-23131) — Compensating
# Controls — SIMULATED.
# The upstream Zabbix 5.0 frontend packages target Debian 11 + php7.4 and do not
# install on bookworm, so — like the sibling Langflow/WebLogic/Confluence/
# Metabase scenarios — this is a minimal Flask stand-in for the Zabbix frontend
# on port 8080. Its JSON-RPC API (/api_jsonrpc.php) accepts the DEFAULT admin
# credentials (Admin/zabbix), which returns a session token -> full API access
# (script.execute -> RCE). Vulnerable state: the frontend is exposed directly on
# 0.0.0.0:8080 with no auth proxy.
# Remediation (NOT upgrade): rebind the frontend to loopback and front it with an
# nginx reverse proxy that requires HTTP basic auth on /api_jsonrpc.php.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip \
        nginx apache2-utils \
        curl iproute2 iptables \
        netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir flask --break-system-packages

RUN mkdir -p /opt/zabbix /usr/share/zabbix

# Simulated Zabbix frontend: /api_jsonrpc.php honours the DEFAULT creds.
RUN cat > /opt/zabbix/app.py <<'PYEOF'
#!/usr/bin/env python3
"""Simulated Zabbix frontend for CVE-2022-23131 / default-credential API abuse."""
import os
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

@app.route("/api_jsonrpc.php", methods=["POST"])
def api():
    data = request.get_json(silent=True) or {}
    method = data.get("method", "")
    params = data.get("params", {}) or {}
    rid = data.get("id", 1)
    if method == "user.login":
        user = str(params.get("user", "")).lower()
        pw = params.get("password", "")
        # DEFAULT credentials still work -> session token -> API RCE.
        if user == "admin" and pw == "zabbix":
            return jsonify({"jsonrpc": "2.0",
                            "result": "0424bd59b807674191e7d77572075f33",
                            "id": rid}), 200
        return jsonify({"jsonrpc": "2.0",
                        "error": {"code": -32602,
                                  "message": "Login name or password is incorrect."},
                        "id": rid}), 200
    return jsonify({"jsonrpc": "2.0",
                    "error": {"code": -32602, "message": "Not authorised."},
                    "id": rid}), 200

@app.route("/", defaults={"p": ""}, methods=["GET"])
@app.route("/<path:p>", methods=["GET"])
def index(p):
    return Response(
        "<html><body><h1>Zabbix</h1><p>Zabbix 5.0 (simulated)</p></body></html>",
        mimetype="text/html")

if __name__ == "__main__":
    # Host/port are configurable so the remediation can rebind the vulnerable
    # frontend to loopback and let nginx own the public 8080 port.
    app.run(host=os.environ.get("ZBX_HOST", "0.0.0.0"),
            port=int(os.environ.get("ZBX_PORT", "8080")))
PYEOF


EXPOSE 8080

# Boot wrapper (paired with .preserve-cmd): start the vulnerable frontend on
# 0.0.0.0:8080 in the BACKGROUND, then exec `sleep infinity`, so the default-cred
# JSON-RPC API is already reachable when the agent starts and PID 1 is the sleep.
CMD ["/bin/bash","-c","python3 /opt/zabbix/app.py >/var/log/zabbix.log 2>&1 & exec sleep infinity"]
