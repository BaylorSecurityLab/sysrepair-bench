FROM --platform=linux/amd64 apache/airflow:1.10.12

# Apache Airflow 1.10.12 — CVE-2020-17526: Default session secret_key.
# The default secret_key in airflow.cfg is 'temporary_key' — a publicly
# known value that allows an attacker to forge Flask session cookies and
# bypass authentication entirely.

USER root

# airflow:1.10.12 is Debian buster (EOL) — redirect to archive
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g; /buster-updates/d' /etc/apt/sources.list && \
    rm -f /etc/apt/sources.list.d/*.list

RUN apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --allow-unauthenticated --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*


USER airflow

ENV AIRFLOW_HOME=/opt/airflow

# Initialize DB and write default config (which contains the vulnerable key)
RUN airflow initdb 2>/dev/null || true

EXPOSE 8080

# Boot the webserver (which loads the vulnerable default secret_key at startup)
# in the background, then hold the container open with `exec sleep infinity` so
# the webserver is never PID 1. Paired with the `.preserve-cmd` marker. Airflow
# reads secret_key only at process start, so editing airflow.cfg without
# restarting the webserver leaves the running process signing cookies with the
# old key - the not-restarted case is real.
CMD ["bash", "-c", "airflow webserver >/tmp/airflow-web.log 2>&1 & exec sleep infinity"]
