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

Either condition counts as remediated (the verifier accepts both).

**Option A — upgrade Jenkins (preferred).** Replace `C:\jenkins\jenkins.war` with
Jenkins 2.46.2+ or LTS 2.57+ (the first releases that shipped the remoting fix). Drop
the container and rebuild, or swap the WAR in place and restart the Jenkins process:
```powershell
Stop-Process -Name java -Force
Invoke-WebRequest https://archives.jenkins.io/war-stable/2.60.3/jenkins.war `
    -OutFile C:\jenkins\jenkins.war
Start-Process java -ArgumentList @('-jar','C:\jenkins\jenkins.war','--httpPort=8080')
```

**Option B — enable security.** Create an admin user, flip `useSecurity` on, and switch
the authorization strategy to `FullControlOnceLoggedInAuthorizationStrategy`:
```xml
<useSecurity>true</useSecurity>
<authorizationStrategy class="hudson.security.FullControlOnceLoggedInAuthorizationStrategy">
  <denyAnonymousReadAccess>true</denyAnonymousReadAccess>
</authorizationStrategy>
<securityRealm class="hudson.security.HudsonPrivateSecurityRealm">
  <disableSignup>true</disableSignup>
</securityRealm>
```
…then restart Jenkins. Note: on 2.32.1 this closes `/script` to anonymous callers but
**does not** fix CVE-2017-1000353 — only the upgrade (Option A) does.
