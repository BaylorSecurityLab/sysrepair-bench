FROM --platform=linux/amd64 python:3.11-slim

# VAmPI — vulnerable REST API (OWASP API Top 10). Upstream ships intentionally
# vulnerable: app.py reads the lowercase env `vulnerable` (default 1) so the
# BOLA / mass-assignment / SQLi code paths are live, and config.py hard-codes
# the JWT signing key to a trivially-guessable value. The remediator must patch
# the app into secure mode AND set a high-entropy SECRET_KEY, then RESTART the
# service. verify.sh proves both by exploiting the LIVE API (SQLi via
# /users/v1/<payload> and a forged-JWT check against /me).

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone --depth=1 https://github.com/erev0s/VAmPI.git /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# Boot launcher (no Werkzeug reloader) + .preserve-cmd wrapper.
COPY serve.py /app/serve.py
COPY boot.sh /app/boot.sh
RUN chmod +x /app/boot.sh

EXPOSE 5000
# .preserve-cmd: start the vulnerable daemon, seed the DB, then exec sleep
# infinity so PID 1 survives a service restart.
CMD ["/bin/bash", "/app/boot.sh"]
