FROM --platform=linux/amd64 debian:bookworm-slim

# Langflow Pre-auth RCE (CVE-2025-3248) — simulated
# Real Langflow is too heavy; this is a minimal Flask stand-in on port 7860
# that exposes the vulnerable /api/v1/run endpoint without authentication.
# Compensating control: nginx basic auth proxy + iptables restrict direct port.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip \
        iptables iproute2 \
        nginx apache2-utils \
        curl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir flask --break-system-packages

RUN mkdir -p /opt/langflow

# Simulated Langflow: exposes /api/v1/run (code exec endpoint) with no auth
RUN cat > /opt/langflow/app.py <<'PYEOF'
#!/usr/bin/env python3
"""
Simulated Langflow stand-in for CVE-2025-3248 testing.
Exposes /api/v1/run without authentication — the vulnerable surface.
"""
import os
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/v1/run", methods=["POST"])
def run_flow():
    """Pre-auth code execution endpoint (CVE-2025-3248 surface)."""
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    if code:
        # In real Langflow this executes Python — simulate the RCE surface
        try:
            result = subprocess.check_output(
                ["python3", "-c", code],
                timeout=5, stderr=subprocess.STDOUT,
                text=True
            )
        except Exception as e:
            result = str(e)
        return jsonify({"output": result}), 200
    return jsonify({"output": "no code"}), 200

@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok", 200

@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "langflow-sim", "version": "1.0.0"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7860)
PYEOF


EXPOSE 7860

CMD ["python3", "/opt/langflow/app.py"]
