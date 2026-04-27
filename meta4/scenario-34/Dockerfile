FROM --platform=linux/amd64 ubuntu:22.04

# docker.sock bind-mount — container escape via Docker API (misconfig).
# An application container with /var/run/docker.sock mounted allows any
# process inside to control the host Docker daemon and escape the
# container sandbox.

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl python3 python3-pip socat && \
    rm -rf /var/lib/apt/lists/* && \
    pip3 install --no-cache-dir flask

# Create an unprivileged app user
RUN useradd -r -m -s /bin/bash appuser

# Simulate a bind-mounted docker.sock — create it as a regular file
# (simulating the mount point) world-readable/writable
RUN touch /var/run/docker.sock && chmod 0666 /var/run/docker.sock

# Create a simple Flask app that the scenario's "service" runs
RUN mkdir -p /app && cat > /app/server.py <<'PYEOF'
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "OK\n", 200

@app.route("/health")
def health():
    return "healthy\n", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
PYEOF

RUN chown -R appuser:appuser /app


EXPOSE 8080
USER appuser
CMD ["python3", "/app/server.py"]
