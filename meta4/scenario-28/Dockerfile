FROM --platform=linux/amd64 python:3.11-slim

# OWASP crAPI — BOLA and mass-assignment vulnerabilities.
# Full crAPI is a 7-service compose stack. This scenario implements a
# focused Flask API with real BOLA on GET /videos/<id> (no ownership
# check) and real mass-assignment on POST /profile (accepts arbitrary
# JSON fields including is_admin). Both are genuine, exploitable flaws —
# verify.sh confirms exploitation fails after remediation and that
# legitimate operations still work.

WORKDIR /app
COPY app /app
RUN pip install --no-cache-dir flask==3.0.0 pyjwt==2.8.0

EXPOSE 8888
CMD ["python", "app.py"]
