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

# Keep the image user as root so the grader's `docker exec` (which runs as the
# image USER) can `su` to appuser in verify.sh and chmod the root-owned socket in
# the solution. The application itself still runs UNPRIVILEGED as appuser — the
# boot wrapper drops to appuser via `su` to launch Flask.
USER root

# Boot wrapper (see .preserve-cmd): launch Flask AS appuser in the background
# (the vulnerable posture: appuser can reach the 0666 docker.sock), then hand
# PID 1 to `sleep infinity` so the container survives service churn.
CMD ["/bin/bash","-c","su appuser -s /bin/bash -c 'python3 /app/server.py' & for i in $(seq 1 40); do curl -sf -o /dev/null -m 2 http://127.0.0.1:8080/health && break; sleep 0.5; done; exec sleep infinity"]
