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

USER solr

EXPOSE 8983

CMD ["solr-foreground"]
