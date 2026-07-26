FROM --platform=linux/amd64 eclipse-temurin:11-jdk-jammy

# Log4j 2.17.0 JDBC Appender RCE — CVE-2021-44832.
# The JDBC Appender accepted a JNDI data-source name from configuration,
# letting an attacker who can influence the config trigger RCE via LDAP.

WORKDIR /opt/app

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -fsSLo log4j-core-2.17.0.jar https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.17.0/log4j-core-2.17.0.jar && \
    curl -fsSLo log4j-api-2.17.0.jar  https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.17.0/log4j-api-2.17.0.jar && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY app /opt/app
RUN cd /opt/app && javac -cp "log4j-core-2.17.0.jar:log4j-api-2.17.0.jar" App.java

EXPOSE 8080

# .preserve-cmd: boot the app in the BACKGROUND (kept mainly as a regression
# target - the app must still run on the patched classpath) and keep PID 1 as
# `sleep infinity`. NB: CVE-2021-44832 is not remotely triggerable against the
# running JVM; the exposure is gated on the log4j-core artifact ON DISK that a
# config-controlling attacker would load via a JDBC appender. The verifier
# therefore exercises the on-disk jar's JDBC/JNDI code path directly.
CMD ["/bin/bash","-c","java -cp /opt/app:/opt/app/log4j-core-2.17.0.jar:/opt/app/log4j-api-2.17.0.jar App >/var/log/app.log 2>&1 & exec sleep infinity"]
