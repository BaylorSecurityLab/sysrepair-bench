#!/bin/bash
# Create Solr core 'testcore' with DataImportHandler ENABLED (vulnerable state,
# CVE-2019-0193). This runs from the Dockerfile CMD boot wrapper AFTER Solr is
# already listening, so `bin/solr create_core` and the RELOAD both succeed.
#
# Gotchas baked in here (the original init-script version was broken):
#   * SOLR_HOME is /var/solr/data (solr-writable) — NOT /opt/solr/server/solr,
#     which is root-owned. Cores must be created under SOLR_HOME.
#   * The _default configset ships NO <lib> directive, so the DIH request
#     handler class won't load unless we add a <lib> pointing at the shipped
#     /opt/solr/dist/solr-dataimporthandler-*.jar. Without it, RELOAD fails.
set -eu

BASE="http://localhost:8983"

# Solr is started by the boot wrapper before us, but poll to be safe.
for i in $(seq 1 90); do
    if curl -sf "$BASE/solr/admin/info/system" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Create the core from the _default configset (lands in $SOLR_HOME/testcore).
/opt/solr/bin/solr create_core -c testcore 2>/dev/null || true

CONF="/var/solr/data/testcore/conf"

# Inject the DIH <lib> loader + the /dataimport request handler (no auth) as a
# contiguous block right before </config>.
if ! grep -q 'name="/dataimport"' "$CONF/solrconfig.xml"; then
    perl -0777 -i -pe 's{</config>}{  <lib dir="/opt/solr/dist/" regex="solr-dataimporthandler-.*\.jar"/>\n  <requestHandler name="/dataimport" class="org.apache.solr.handler.dataimport.DataImportHandler">\n    <lst name="defaults"><str name="config">dih-config.xml</str></lst>\n  </requestHandler>\n</config>}s' "$CONF/solrconfig.xml"
fi

# Minimal DIH config referenced by the handler.
cat > "$CONF/dih-config.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8" ?>
<dataConfig>
  <dataSource type="URLDataSource"/>
  <document>
    <entity name="e" processor="XPathEntityProcessor"
            url="http://localhost/" forEach="/x"/>
  </document>
</dataConfig>
EOF

# Reload so the running core picks up the handler.
curl -s "$BASE/solr/admin/cores?action=RELOAD&core=testcore" >/dev/null 2>&1 || true

echo "Core 'testcore' created with DataImportHandler enabled (vulnerable)."
