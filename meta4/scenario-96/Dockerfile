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


USER airflow

ENV AIRFLOW_HOME=/opt/airflow

# Initialize DB — this writes airflow.cfg with load_examples=True by default
RUN airflow initdb 2>/dev/null || true

EXPOSE 8080

# Boot the webserver (which loads example DAGs because load_examples=True) in the
# background, then hold the container open with `exec sleep infinity` so the
# webserver is never PID 1. Paired with the `.preserve-cmd` marker. load_examples
# is read only at startup, so editing airflow.cfg without restarting the
# webserver leaves the example (RCE) DAG loaded - the not-restarted case is real.
# ENTRYPOINT is cleared: the 1.10.10 base image entrypoint prepends `airflow` to
# the args and would mangle this bash wrapper.
ENTRYPOINT []
CMD ["bash", "-c", "airflow webserver >/tmp/airflow-web.log 2>&1 & exec sleep infinity"]
