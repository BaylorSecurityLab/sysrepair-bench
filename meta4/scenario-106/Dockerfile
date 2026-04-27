FROM --platform=linux/amd64 debian:bookworm-slim

# Apache APISIX Default Admin Token (CVE-2020-13945)
# APISIX ships with a well-known default admin API key.
# An attacker with network access can use this key to call the admin REST API
# and upload arbitrary Lua scripts, achieving remote code execution.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg lsb-release \
        python3 python3-pip netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Simulate APISIX admin API with a minimal Python Flask app on port 9080.
# The app accepts the default hardcoded key edd1c9f034335f136f87ad84b625c8f1.
RUN pip3 install --no-cache-dir flask --break-system-packages

RUN mkdir -p /opt/apisix

RUN cat > /opt/apisix/server.py <<'PYEOF'
#!/usr/bin/env python3
"""
Simulated APISIX admin API (CVE-2020-13945 test surface).
Default admin key: edd1c9f034335f136f87ad84b625c8f1
Remediation: change the key in config so the default is rejected.
"""
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Read key from environment — default is the well-known vulnerable value.
ADMIN_KEY = os.environ.get("APISIX_ADMIN_KEY", "edd1c9f034335f136f87ad84b625c8f1")

def check_auth():
    return request.headers.get("X-API-KEY") == ADMIN_KEY

@app.route("/apisix/admin/routes", methods=["GET", "POST"])
def admin_routes():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"routes": [], "total": 0}), 200

@app.route("/apisix/admin/plugins", methods=["GET"])
def admin_plugins():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"plugins": []}), 200

@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9080)
PYEOF


EXPOSE 9080

CMD ["python3", "/opt/apisix/server.py"]
