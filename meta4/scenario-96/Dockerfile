FROM --platform=linux/amd64 apache/airflow:1.10.10

# Apache Airflow 1.10.10 — CVE-2020-11978: Example DAGs enabled by default.
# The example DAG 'example_trigger_target_dag' accepts arbitrary bash commands
# via its 'message' parameter — enabling remote code execution for any user
# with DAG trigger permissions.

USER root

# airflow:1.10.10 is Debian buster (EOL) — redirect to archive
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org/debian-security|archive.debian.org/debian-security|g; /buster-updates/d' /etc/apt/sources.list && \
    rm -f /etc/apt/sources.list.d/*.list

RUN apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --allow-unauthenticated --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY verify.sh /opt/verify.sh
RUN chmod +x /opt/verify.sh

USER airflow

ENV AIRFLOW_HOME=/opt/airflow

# Initialize DB — this writes airflow.cfg with load_examples=True by default
RUN airflow initdb 2>/dev/null || true

EXPOSE 8080

CMD ["airflow", "webserver"]
