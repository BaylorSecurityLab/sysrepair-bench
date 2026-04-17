#!/bin/bash
# Create a Solr core named 'testcore' with DataImportHandler enabled.
# This runs after Solr starts in the official solr Docker image.
set -e

# Wait for Solr to be ready
for i in $(seq 1 30); do
    if curl -sf "http://localhost:8983/solr/admin/cores?action=STATUS" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

# Create core
/opt/solr/bin/solr create_core -c testcore 2>/dev/null || true

# Add DIH configuration to testcore (vulnerable state: DIH enabled with no auth)
CORE_CONF=/opt/solr/server/solr/testcore/conf
mkdir -p "$CORE_CONF"

# Add DIH handler to solrconfig.xml
if [ -f "$CORE_CONF/solrconfig.xml" ]; then
    # Insert DIH requestHandler before closing config tag
    if ! grep -q "dataimport" "$CORE_CONF/solrconfig.xml"; then
        sed -i 's|</config>|  <requestHandler name="/dataimport" class="org.apache.solr.handler.dataimport.DataImportHandler">\n    <lst name="defaults">\n      <str name="config">dih-config.xml</str>\n    </lst>\n  </requestHandler>\n</config>|' \
            "$CORE_CONF/solrconfig.xml"
    fi
fi

# Create a basic DIH config file
cat > "$CORE_CONF/dih-config.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8" ?>
<dataConfig>
  <dataSource type="FileDataSource"/>
  <document>
    <entity name="test" processor="FileListEntityProcessor"
            baseDir="/tmp" fileName=".*\.txt"
            transformer="TemplateTransformer">
      <field column="name" name="id"/>
    </entity>
  </document>
</dataConfig>
EOF

echo "Core 'testcore' created with DIH enabled."
