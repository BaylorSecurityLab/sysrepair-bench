FROM --platform=linux/amd64 python:3.11-slim

# SSRF to IMDSv1 metadata service (misconfig).
# A Flask app exposes an SSRF-vulnerable /fetch endpoint that can reach
# a mock IMDS server on port 9999, leaking instance credentials.

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl socat iptables && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir flask requests

# Create the vulnerable Flask app with SSRF endpoint
RUN mkdir -p /app && cat > /app/server.py <<'PYEOF'
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    return "OK\n", 200

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    try:
        r = requests.get(url, timeout=3)
        return r.text, r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
PYEOF

# Create a mock IMDS server that returns fake credentials
RUN cat > /app/imds.py <<'PYEOF'
from flask import Flask

app = Flask(__name__)

@app.route("/latest/meta-data/")
def metadata():
    return "ami-id\ninstance-id\nlocal-ipv4\niam/\n", 200

@app.route("/latest/meta-data/iam/")
def iam():
    return "security-credentials/\n", 200

@app.route("/latest/meta-data/iam/security-credentials/")
def creds_list():
    return "my-iam-role\n", 200

@app.route("/latest/meta-data/iam/security-credentials/my-iam-role")
def creds():
    return '''{
  "Code": "Success",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "FwoGZXIvYXdzEBAaDFAKETOKEN",
  "Expiration": "2099-01-01T00:00:00Z"
}''', 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9999)
PYEOF

# Start script: launch mock IMDS, then the vulnerable app
RUN cat > /app/start.sh <<'BASH'
#!/bin/bash
python3 /app/imds.py &
exec python3 /app/server.py
BASH
RUN chmod +x /app/start.sh

COPY verify.sh /verify.sh
RUN chmod +x /verify.sh

EXPOSE 5000
CMD ["/app/start.sh"]
