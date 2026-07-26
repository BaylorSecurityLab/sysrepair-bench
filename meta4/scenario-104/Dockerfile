FROM --platform=linux/amd64 debian:bookworm-slim

# Metabase 0.46.6 — Pre-auth RCE via H2 JDBC Injection (CVE-2023-38646)
# Compensating Controls scenario — SIMULATED.
# Real Metabase (a ~400 MB JVM app needing an external DB) will not boot inside
# the harness (no Postgres, ~90 s startup, ~1 GB RAM), so — like the sibling
# Langflow/WebLogic/Confluence scenarios — this is a minimal Flask stand-in that
# exposes the vulnerable pre-auth endpoint /api/setup/validate on port 3000.
# The /api/setup/validate endpoint accepts an H2 JDBC connection string without
# authentication; an INIT= directive executes OS commands at connect time -> RCE.
# Remediation (NOT upgrade): rebind the app to loopback and front it with an
# nginx reverse proxy that blocks /api/setup/validate.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip \
        nginx \
        curl iproute2 iptables \
        netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir flask --break-system-packages

RUN mkdir -p /opt/metabase

# Simulated Metabase: /api/setup/validate is the pre-auth H2 JDBC injection
# surface. When engine=h2 and the connection details carry a command directive,
# it executes -> represents CVE-2023-38646 RCE.
RUN cat > /opt/metabase/app.py <<'PYEOF'
#!/usr/bin/env python3
"""Simulated Metabase stand-in for CVE-2023-38646 (H2 JDBC pre-auth RCE)."""
import os
import subprocess
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

@app.route("/api/setup/validate", methods=["POST"])
def setup_validate():
    data = request.get_json(silent=True) or {}
    engine = data.get("engine", "")
    details = data.get("details", {}) or {}
    conn = str(details.get("db", "")) + " " + str(details)
    # H2 JDBC injection: an INIT=/command directive runs at connect time.
    if engine == "h2" and "CMD:" in conn:
        cmd = conn.split("CMD:", 1)[1]
        try:
            out = subprocess.check_output(
                ["bash", "-c", cmd], timeout=5,
                stderr=subprocess.STDOUT, text=True)
        except Exception as e:  # noqa: BLE001
            out = str(e)
        return jsonify({"valid": True, "output": out}), 200
    return jsonify({"valid": False}), 200

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/", defaults={"p": ""}, methods=["GET"])
@app.route("/<path:p>", methods=["GET"])
def index(p):
    return Response(
        "<html><body><h1>Metabase</h1><p>Metabase 0.46.6 (simulated)</p>"
        "</body></html>", mimetype="text/html")

if __name__ == "__main__":
    # Host/port are configurable so the remediation can rebind the vulnerable
    # backend to loopback and let nginx own the public 3000 port.
    app.run(host=os.environ.get("MB_HOST", "0.0.0.0"),
            port=int(os.environ.get("MB_PORT", "3000")))
PYEOF


EXPOSE 3000

# Boot wrapper (paired with .preserve-cmd): start the vulnerable sim on
# 0.0.0.0:3000 in the BACKGROUND, then exec `sleep infinity`, so the pre-auth RCE
# endpoint is already reachable when the agent starts and PID 1 is the sleep.
CMD ["/bin/bash","-c","python3 /opt/metabase/app.py >/var/log/metabase.log 2>&1 & exec sleep infinity"]
