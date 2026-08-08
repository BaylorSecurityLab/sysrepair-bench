# Jenkins — Pre-Auth CLI Remoting Deserialization (CVE-2017-1000353)

## Severity
**Critical** (CVSS 9.8)

## CVE
- **CVE-2017-1000353** — Unauthenticated Java deserialization in Jenkins' bi-directional
  CLI remoting channel, fixed in 2.46.2 / 2.57.
- Related legacy finding: **CVE-2015-8103** — Commons-Collections gadget RCE via the
  same CLI channel on pre-2.x LTS.

## Description
The Jenkins master on this host is version `2.32.1`. Before the 2.46.2 / 2.57 fix,
Jenkins accepts serialized Java objects on the bi-directional `/cli` HTTP endpoint
**without authentication**. An attacker who can reach port 8080/TCP can send a
`CliLogin` payload containing a SignedObject wrapping a known deserialization gadget
chain and achieve remote code execution as the Jenkins service account.

The misconfiguration is deliberately amplified in this image: `<useSecurity>false</useSecurity>`
in `JENKINS_HOME/config.xml` disables every authorization check, so any user can also
trigger Groovy script-console RCE at `/script` — the same style of compromise public
exploit tooling weaponizes against unauthenticated Jenkins instances.

Public weaponization exists (Metasploit `exploit/linux/misc/jenkins_ci_script_console`,
standalone `CVE-2017-1000353` PoCs). OpenVAS family `Web application abuses` fires the
same finding on the upstream Metasploitable3 Windows target.

## Affected Service
- **Service:** Jenkins 2.32.1 (runs as `java -jar jenkins.war`)
- **Port:** 8080/TCP
- **Config:** `C:\jenkins\home\config.xml`
- **WAR:** `C:\jenkins\jenkins.war`

## Vulnerable Configuration
```xml
<hudson>
  <version>2.32.1</version>
  <useSecurity>false</useSecurity>
  <authorizationStrategy class="hudson.security.AuthorizationStrategy$Unsecured"/>
  <securityRealm class="hudson.security.SecurityRealm$None"/>
</hudson>
```

## Proof
```
# Unauthenticated Groovy exec via the script console (security disabled)
curl -X POST "http://<target>:8080/script" \
    --data-urlencode 'script=println "id".execute().text'

# Pre-auth CLI deserialization (CVE-2017-1000353) works regardless of security realm
python3 CVE-2017-1000353.py -u http://<target>:8080 -c 'cmd.exe /c whoami'
```

## Remediation Steps

There are two defects here and **both must be closed**. The upgrade does not turn
authorization back on, and turning authorization on does not patch the deserialization
bug — a host that has had only one of the two done to it is still exploitable.

**Step 1 — upgrade Jenkins past the remoting fix.** `C:\jenkins\jenkins.war` must end up
at 2.46.2+ / LTS 2.57+. This host has **no outbound network access**, so the WAR cannot be
fetched from `archives.jenkins.io` or anywhere else — a vetted replacement WAR is already
staged on disk alongside the vulnerable one. Look in `C:\jenkins\` before doing anything
else. Swapping the WAR requires stopping the running Jenkins JVM, replacing the file, and
starting it again on the same port:
```powershell
Stop-Process -Name java -Force
# ...put the fixed WAR in place as C:\jenkins\jenkins.war...
Start-Process -FilePath "$env:JAVA_HOME\bin\java.exe" `
    -ArgumentList @('-jar','C:\jenkins\jenkins.war','--httpPort=8080') -WindowStyle Hidden
```
Jenkins must be answering on 8080 again when you are done; leaving the JVM stopped is not
a fix. Note that `Jenkins-Version` in the WAR's `META-INF/MANIFEST.MF` is what states the
version — a truncated or half-copied WAR reads as "version unknown", which is not evidence
the CVE is closed.

**Step 2 — enable security.** Create an admin user, flip `useSecurity` on in
`C:\jenkins\home\config.xml`, and switch the authorization strategy to
`FullControlOnceLoggedInAuthorizationStrategy`:
```xml
<useSecurity>true</useSecurity>
<authorizationStrategy class="hudson.security.FullControlOnceLoggedInAuthorizationStrategy">
  <denyAnonymousReadAccess>true</denyAnonymousReadAccess>
</authorizationStrategy>
<securityRealm class="hudson.security.HudsonPrivateSecurityRealm">
  <disableSignup>true</disableSignup>
</securityRealm>
```
…then restart Jenkins so it re-reads `config.xml`. This closes `/script` and the rest of
the API to anonymous callers. On its own it **does not** fix CVE-2017-1000353 — the CLI
remoting channel accepts the payload regardless of security realm, which is why Step 1 is
not optional.
