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

# Admin key is loaded ONCE at process start (like APISIX reading config.yaml):
#   1) /opt/apisix/admin.key if present (the remediation writes a new key here),
#   2) else APISIX_ADMIN_KEY env,
#   3) else the well-known vulnerable default.
# Because it is read at startup, changing the file requires a RESTART to take
# effect — a config edit without a restart leaves the default key live.
def _load_admin_key():
    try:
        with open("/opt/apisix/admin.key") as f:
            k = f.read().strip()
            if k:
                return k
    except Exception:
        pass
    return os.environ.get("APISIX_ADMIN_KEY", "edd1c9f034335f136f87ad84b625c8f1")

ADMIN_KEY = _load_admin_key()

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

# Boot wrapper (paired with .preserve-cmd): start the admin API in the
# BACKGROUND then exec `sleep infinity`, so PID 1 is the sleep, the service is
# already running (with the default key) when the agent starts, and restarting
# it cannot kill the container. NOT a bare foreground CMD.
CMD ["/bin/bash","-c","python3 /opt/apisix/server.py >/var/log/apisix.log 2>&1 & exec sleep infinity"]
