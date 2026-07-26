FROM --platform=linux/amd64 eclipse-temurin:8-jre-jammy

# Apache Druid 0.20.2 — CVE-2021-25646: JavaScript injection in DataSource
# input filter. When druid.javascript.enabled=true, the coordinator accepts
# JavaScript function bodies in query filter expressions and executes them
# server-side — enabling unauthenticated RCE via a crafted HTTP POST.
# Remediation: set druid.javascript.enabled=false in runtime.properties.
#
# NB: Druid 0.20.2 only officially supports Java 8 and start-nano-quickstart
# REFUSES to launch on Java 11/17 ("Druid only officially supports Java 8"), so
# the vulnerable coordinator never runs on a Java 17 base. We pin Java 8.

ENV DEBIAN_FRONTEND=noninteractive \
    DRUID_VERSION=0.20.2 \
    DRUID_HOME=/opt/druid \
    JAVA_HOME=/opt/java/openjdk

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget ca-certificates \
        perl netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

# Download and install Druid 0.20.2.
# Integrity gate: the fetch is non-hermetic (live archive.apache.org), so the
# exact tarball is sha256-pinned. sha256 of apache-druid-0.20.2-bin.tar.gz;
# cross-verified against Apache's published .sha512. A corrupted or substituted
# download fails `sha256sum -c -` here and the build aborts before extraction.
RUN wget -q "https://archive.apache.org/dist/druid/${DRUID_VERSION}/apache-druid-${DRUID_VERSION}-bin.tar.gz" \
        -O /tmp/druid.tar.gz && \
    echo "4f439247f79297c2aeb75d6de6038206f00e4e82ae12c4634dceffc059bf12ed  /tmp/druid.tar.gz" | sha256sum -c - && \
    tar xzf /tmp/druid.tar.gz -C /opt && \
    mv /opt/apache-druid-${DRUID_VERSION} ${DRUID_HOME} && \
    rm /tmp/druid.tar.gz

# Vulnerable default: JavaScript enabled.
# CVE-2021-25646 executes attacker JS on the QUERY-serving nodes (broker /
# historical / middleManager), NOT the coordinator-overlord — that node never
# runs native queries. Enabling it only on coordinator-overlord (as an earlier
# revision did) left the documented query-path RCE unreachable, so we enable it
# in _common/common.runtime.properties (inherited by every node) so the live
# broker genuinely executes JavaScript aggregators/filters. The leading newline
# is REQUIRED: common.runtime.properties does not end in one, and appending
# without it silently glues the key onto the previous line (never parsed).
RUN printf '\ndruid.javascript.enabled=true\n' >> ${DRUID_HOME}/conf/druid/single-server/nano-quickstart/_common/common.runtime.properties && \
    echo "druid.javascript.enabled=true" >> ${DRUID_HOME}/conf/druid/single-server/nano-quickstart/coordinator-overlord/runtime.properties


EXPOSE 8081

# Boot the Druid nano-quickstart (coordinator/overlord/broker/...) in the
# background, then hold the container open with `exec sleep infinity` so the
# supervisor is never PID 1. Paired with the `.preserve-cmd` marker. A fix that
# edits runtime.properties but never restarts the coordinator leaves JavaScript
# execution enabled on the live process, so the not-restarted case is real.
CMD ["bash", "-c", "${DRUID_HOME}/bin/start-nano-quickstart >/tmp/druid.log 2>&1 & exec sleep infinity"]
