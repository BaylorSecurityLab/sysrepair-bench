FROM --platform=linux/amd64 solr:8.11.0

# Apache Solr 8.11.0 ships with Log4j 2.14.1 (vulnerable to CVE-2021-44228).
# This image intentionally pins that version and leaves the default
# log4j2.xml in place so that user-supplied query parameters are logged
# through the vulnerable pattern layout.

USER root

# Enable JNDI lookup (the Solr distribution disables it via
# log4j2.formatMsgNoLookups=true in bin/solr.in.sh in some packagings; we
# explicitly clear that so the vulnerability is reachable).
RUN sed -i '/formatMsgNoLookups/d' /opt/solr/bin/solr.in.sh || true && \
    echo 'SOLR_OPTS="$SOLR_OPTS -Dlog4j2.formatMsgNoLookups=false"' >> /opt/solr/bin/solr.in.sh

# The benchmark harness runs the agent (and the solution) as the image's
# default user, which for this image is `solr`. Solr's ext/ jar directory and
# bin/ are root-owned in the stock image, so the solr user cannot patch Log4j
# at all -> the scenario would be unsolvable by the agent. Grant the solr
# service account ownership of exactly the two trees a defender needs to patch
# Log4j (drop the vulnerable jars, edit solr.in.sh). Nothing else changes.
RUN chown -R solr:solr /opt/solr/server/lib/ext /opt/solr/bin

USER solr

EXPOSE 8983

# .preserve-cmd: boot Solr in the BACKGROUND so a real daemon is already
# running with the vulnerable Log4j when the agent starts (this makes the
# "patched the jars but never restarted" case detectable), then keep PID 1 as
# `sleep infinity` so an agent restarting Solr can never kill the container.
CMD ["/bin/bash","-c","/opt/solr/bin/solr start && exec sleep infinity"]
