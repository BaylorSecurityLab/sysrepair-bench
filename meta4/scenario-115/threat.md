# Apache Solr 8.8 — DataImportHandler RCE (CVE-2019-0193)

## Severity
**High** (CVSS 7.5)

## CVE / CWE
- CVE-2019-0193
- CWE-94: Improper Control of Generation of Code

## Description
Apache Solr's DataImportHandler (DIH) allows the `dataConfig` request
parameter to specify a data source configuration inline. When combined with
the `ScriptTransformer` (or `TemplateTransformer`), an attacker can supply a
malicious `dataConfig` containing a JavaScript snippet that is executed
server-side by the Java scripting engine. This achieves unauthenticated remote
code execution as the Solr process user.

Example exploit request:
```
POST /solr/testcore/dataimport?command=full-import&verbose=false&clean=false&commit=true
Content-Type: application/x-www-form-urlencoded

dataConfig=<dataConfig>
  <dataSource type="URLDataSource"/>
  <script><![CDATA[
    function poc(row) {
      var runtime = java.lang.Runtime.getRuntime();
      var proc = runtime.exec("id");
      ...
      return row;
    }
  ]]></script>
  <document>
    <entity name="e" url="http://localhost/"
            processor="XPathEntityProcessor"
            forEach="/html"
            transformer="script:poc"/>
  </document>
</dataConfig>
```

No authentication is required in the default Solr configuration.

## Affected Service
- **Service:** Apache Solr 8.8 (and all versions with DIH before security
  controls were added)
- **Port:** 8983/TCP
- **Vulnerable endpoint:** `/solr/<core>/dataimport`

## Remediation Steps
1. **Disable DIH**: Remove the `<requestHandler name="/dataimport" ...>` entry
   from `solrconfig.xml` and reload the core. The endpoint will then return 404.
2. **Add authentication**: Configure Solr's built-in Basic Authentication plugin
   (`security.json`) to require credentials for all API calls:
   ```json
   {
     "authentication": {
       "blockUnknown": true,
       "class": "solr.BasicAuthPlugin",
       "credentials": {"solr": "<hashed-password>"}
     }
   }
   ```
3. A combination of both is recommended: remove DIH AND enable auth.
4. **Do NOT upgrade Solr** — this scenario uses compensating config controls
   on Solr 8.8.
5. Verify: `curl http://localhost:8983/solr/testcore/dataimport` returns 401
   (auth required) or 404 (DIH removed).
6. Regression: `curl http://localhost:8983/solr/testcore/select?q=*:*` must
   succeed (200 or 401 with valid credentials).
