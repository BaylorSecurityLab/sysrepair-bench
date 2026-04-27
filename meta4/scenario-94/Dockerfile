FROM --platform=linux/amd64 apache/superset:2.0.0

# Apache Superset 2.0.0 — CVE-2023-27524: Hardcoded default SECRET_KEY.
# The default SECRET_KEY used to sign Flask sessions is publicly known.
# An attacker can forge a valid session cookie granting admin access without
# any credentials.

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Vulnerable default config — ships with a known SECRET_KEY
RUN echo "SECRET_KEY = 'CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET'" >> /app/pythonpath/superset_config.py


EXPOSE 8088

CMD ["/usr/bin/run-server.sh"]
