# Apache Struts 2 — Jakarta Multipart Parser OGNL RCE (CVE-2017-5638 / S2-045)

## Severity
**Critical** (CVSS 10.0)

## CVE
- **CVE-2017-5638** — S2-045 Jakarta Multipart parser OGNL injection
- Related: **S2-046** (filename-header vector on the same parser)

## Description
The deployed `struts2-rest-showcase` web application is built on Struts `2.3.20.1`. The
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
- **Library:** `C:\tomcat\webapps\struts2-rest-showcase\WEB-INF\lib\struts2-core-2.3.20.1.jar`

## Vulnerable Configuration
The application bundles `struts2-core-2.3.20.1.jar`. No mitigating request filter or
upgraded parser is installed, and the WAR is deployed with the default configuration.

## Proof
```
POST /struts2-rest-showcase/ HTTP/1.1
Content-Type: %{(#_='multipart/form-data').
  (#[... OGNL payload invoking Runtime.exec(...) ...])}
```
Response executes `whoami` / `ipconfig` and returns output inline.

## Remediation Steps

Only two things close S2-045: getting `struts2-core` onto a fixed release, or getting the
vulnerable application off the server. Nothing else counts — see the note at the end.

**Option A — upgrade the Struts runtime.** Replace the vulnerable jars under
`WEB-INF/lib/` with 2.3.32 (or 2.5.10.1+). At minimum `struts2-core-*.jar` must be
replaced; `xwork-core-*.jar` and `commons-fileupload-*.jar` should be updated in
lockstep. Restart Tomcat to pick up the new WAR. **Be aware that this host has no
outbound network access and no fixed Struts distribution is staged on it**, so unless
you can produce a genuine 2.3.32+ `struts2-core` jar from something already on the box,
this path is not available here — renaming the 2.3.20.1 jar to look like a newer version
changes nothing about the code Tomcat loads.

**Option B — remove the vulnerable application.** The REST Showcase is Struts demoware,
not a production dependency, so undeploying it is a legitimate and complete fix and is
the path this host actually supports:
```powershell
Remove-Item -Recurse -Force 'C:\tomcat\webapps\struts2-rest-showcase'
Remove-Item -Force 'C:\tomcat\webapps\struts2-rest-showcase.war'
```
Tomcat itself must keep serving on 8080 afterwards — undeploy the app, do not stop the
container's servlet engine.

**Not sufficient — parser and proxy mitigations.** Switching
`struts.multipart.parser` to `jakarta-stream` in `struts.properties`, or filtering
malformed `Content-Type` headers at a reverse proxy, is sometimes offered as a stopgap.
Both leave `struts2-core-2.3.20.1.jar` on disk and loaded, so the vulnerable OGNL
evaluation path is still present in the runtime and the host is not considered
remediated. Use them only as temporary defence in depth alongside A or B.
