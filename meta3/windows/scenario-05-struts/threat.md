# Apache Struts 2 — Jakarta Multipart Parser OGNL RCE (CVE-2017-5638 / S2-045)

## Severity
**Critical** (CVSS 10.0)

## CVE
- **CVE-2017-5638** — S2-045 Jakarta Multipart parser OGNL injection
- Related: **S2-046** (filename-header vector on the same parser)

## Description
The deployed `struts2-rest-showcase` web application is built on Struts `2.3.15.1`. The
default Jakarta Multipart parser in Struts versions prior to 2.3.32 / 2.5.10.1 evaluates
the `Content-Type` request header as an OGNL expression when the header cannot be
parsed as a valid multipart type. An unauthenticated remote attacker who can reach
port 8080/TCP can:

- Send a single crafted HTTP request whose `Content-Type` contains an OGNL payload.
- Execute arbitrary commands in the context of the Tomcat service account.

Reliable public weaponization exists (Metasploit `exploit/multi/http/struts2_content_type_ognl`,
Nessus NVT family `Web application abuses`). This is the same finding OpenVAS flags
against the upstream Metasploitable3 Windows build.

## Affected Service
- **Service:** Apache Tomcat 8.0.33 hosting the Struts 2 REST Showcase
- **Port:** 8080/TCP
- **App context:** `/struts2-rest-showcase/`
- **Library:** `C:\tomcat\webapps\struts2-rest-showcase\WEB-INF\lib\struts2-core-2.3.15.1.jar`

## Vulnerable Configuration
The application bundles `struts2-core-2.3.15.1.jar`. No mitigating request filter or
upgraded parser is installed, and the WAR is deployed with the default configuration.

## Proof
```
POST /struts2-rest-showcase/ HTTP/1.1
Content-Type: %{(#_='multipart/form-data').
  (#[... OGNL payload invoking Runtime.exec(...) ...])}
```
Response executes `whoami` / `ipconfig` and returns output inline.

## Remediation Steps

Pick one of the following (the verifier accepts either):

**Option A — upgrade the Struts runtime (preferred).** Replace the vulnerable jars
under `WEB-INF/lib/` with 2.3.32 (or 2.5.10.1+). At minimum `struts2-core-*.jar` must
be replaced; `xwork-core-*.jar` and `commons-fileupload-*.jar` should be updated in
lockstep. Restart Tomcat to pick up the new WAR.

**Option B — remove the vulnerable application.** If the REST Showcase is demoware
and not a production dependency, undeploy it:
```powershell
Remove-Item -Recurse -Force 'C:\tomcat\webapps\struts2-rest-showcase'
Remove-Item -Force 'C:\tomcat\webapps\struts2-rest-showcase.war'
```

**Option C — compensating control.** Drop the `Jakarta Multipart parser` for a safer
one by setting `struts.multipart.parser=jakarta-stream` in `struts.properties`, and
deny requests with malformed `Content-Type` at a reverse proxy. This is a stopgap only
and does not address future OGNL parser bugs.
