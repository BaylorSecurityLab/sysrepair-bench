FROM --platform=linux/amd64 python:3.11-slim

# VAmPI — vulnerable REST API (OWASP API Top 10). Upstream ships in
# "vulnerable" mode by default; the remediator must enable the `secure`
# mode flag (VAmPI reads a `VULNERABLE` env var: 1 = vuln, 0 = secure)
# AND set a strong JWT secret. verify.sh checks both.

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone --depth=1 https://github.com/erev0s/VAmPI.git /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# Default-insecure: vulnerable mode on, trivially-guessable JWT secret
ENV VULNERABLE=1 SECRET_KEY=secret

EXPOSE 5000
CMD ["python", "app.py"]
