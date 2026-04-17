FROM --platform=linux/amd64 apache/airflow:1.10.12

# Apache Airflow 1.10.12 — CVE-2020-17526: Default session secret_key.
# The default secret_key in airflow.cfg is 'temporary_key' — a publicly
# known value that allows an attacker to forge Flask session cookies and
# bypass authentication entirely.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

USER airflow

ENV AIRFLOW_HOME=/opt/airflow

# Initialize DB and write default config (which contains the vulnerable key)
RUN airflow initdb 2>/dev/null || true

EXPOSE 8080

CMD ["airflow", "webserver"]
