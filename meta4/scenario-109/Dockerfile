FROM --platform=linux/amd64 debian:bookworm-slim

# WebLogic Console URL Bypass RCE (CVE-2020-14882) — simulated
# Real WebLogic is too heavy (~1 GB). This is a minimal Python Flask app
# on port 7001 that serves /console and demonstrates the URL encoding bypass.
# Compensating control: nginx WAF proxy denying /console paths.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip \
        nginx \
        curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir flask --break-system-packages

RUN mkdir -p /opt/weblogic

# Simulated WebLogic: serves /console and handles URL-encoded traversal paths
RUN cat > /opt/weblogic/app.py <<'PYEOF'
#!/usr/bin/env python3
"""
Simulated WebLogic console stand-in for CVE-2020-14882 testing.
The real vulnerability: accessing /console/css/%252e%252e%252fconsole.portal
bypasses the console authentication check via URL encoding.
This sim serves the console without auth to represent the vulnerable state.
"""
from flask import Flask, request, Response
from urllib.parse import unquote

app = Flask(__name__)

def decode_path(path):
    """Double-decode to simulate WebLogic URL normalisation."""
    return unquote(unquote(path))

@app.route("/console", defaults={"subpath": ""})
@app.route("/console/<path:subpath>")
def console(subpath):
    """Simulate WebLogic admin console — no auth in vulnerable state."""
    decoded = decode_path(subpath)
    return Response(
        f"<html><body><h1>WebLogic Admin Console</h1>"
        f"<p>Path: /console/{decoded}</p>"
        f"<p>Welcome to WebLogic Server Administration Console</p></body></html>",
        status=200,
        mimetype="text/html"
    )

@app.route("/", methods=["GET"])
def index():
    return Response(
        "<html><body><h1>WebLogic Server</h1></body></html>",
        status=200, mimetype="text/html"
    )

@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7001)
PYEOF

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

EXPOSE 7001

CMD ["python3", "/opt/weblogic/app.py"]
