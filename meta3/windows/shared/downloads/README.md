# meta3/windows shared downloads

Binary artifacts that the meta3 Windows scenario Dockerfiles `COPY` into their
images. We pre-stage them on the host instead of having every container fetch
them from the internet during `docker build`, because:

* The original upstream archives (`archive.apache.org`, `repo.jenkins-ci.org`,
  `windows.php.net/archives`, `legacy-downloads.mariadb.com`, ...) reset
  connections mid-download often enough that 10+ minute Windows builds fail
  routinely.
* Server Core Windows containers re-fetch each layer's downloads on every cache
  miss; pre-staging cuts wall-clock build time noticeably.

## Layout

Every scenario Dockerfile that needs an artifact references it as
`shared/downloads/<filename>`. That path resolves because [task.py:610](../../../inspect_eval/sysrepair_bench/task.py#L610)
widens the build context to `meta3/windows/` whenever a `shared/` sibling
exists. The `base` image build is the one exception — see
[run.py](../../../inspect_eval/sysrepair_bench/run.py) for how its context is
widened to `meta3/windows/` for the same reason.

## Fetching / refreshing

Run the PowerShell helper from this repo root:

```powershell
pwsh meta3/windows/shared/download-all.ps1
```

It is idempotent: files already present whose sha256 matches `manifest.json`
are skipped. Network errors retry with exponential backoff. If a URL goes dead
upstream, mirror the file somewhere reachable and update `manifest.json`.

## Artifacts

| File | Source | Used by |
|---|---|---|
| `OpenSSH-Win64-v9.5.0.0p1-Beta.zip` | github.com/PowerShell/Win32-OpenSSH releases (v9.5.0.0p1-Beta) | `base/`, `scenario-21-ssh-defaults/` (staged fixed build for the solution) |
| `OpenSSH-Win64-v7.7.2.0p1-Beta.zip` | github.com/PowerShell/Win32-OpenSSH releases (v7.7.2.0p1-Beta) | `scenario-21-ssh-defaults/` |
| `OpenJDK8U-jre_x64_windows_hotspot_8u402b06.zip` | github.com/adoptium/temurin8-binaries (8u402-b06) | scenarios 04, 05, 06, 08 |
| `OpenJDK8U-jdk_x64_windows_hotspot_8u402b06.zip` | github.com/adoptium/temurin8-binaries (8u402-b06, JDK build) | `scenario-07-glassfish/` |
| `OpenJDK8U-jre_x64_windows_hotspot_8u312b07.zip` | github.com/adoptium/temurin8-binaries (8u312-b07, last build that doesn't break ES 1.x JNI) | `scenario-09-elasticsearch/` |
| `apache-tomcat-8.0.33-windows-x64.zip` | archive.apache.org/dist/tomcat/tomcat-8/v8.0.33 | scenarios 04, 05, 08 |
| `jenkins-war-2.32.1.war` | repo.jenkins-ci.org (Artifactory mirror — archives.jenkins.io dropped 2.32.x weeklies) | `scenario-06-jenkins/` (baseline vulnerable WAR) |
| `jenkins-2.60.3.war` | get.jenkins.io/war-stable/2.60.3 (first LTS past the CVE-2017-1000353 fix) | `scenario-06-jenkins/` (staged fixed WAR for the solution) |
| `struts-2.3.20.1-apps.zip` | archive.apache.org/dist/struts/2.3.20.1 (oldest still-published version in the CVE-2017-5638 range) | `scenario-05-struts/` |
| `axis2-1.6.0-war.zip` | archive.apache.org/dist/axis/axis2/java/core/1.6.0 | `scenario-08-axis2/` |
| `glassfish-4.0.zip` | download.oracle.com/glassfish/4.0/release | (superseded — see 4.1.1 below) |
| `glassfish-4.1.1.zip` | download.oracle.com/glassfish/4.1.1/release | `scenario-07-glassfish/` (CVE-2017-1000028 canonical vulnerable build) |
| `elasticsearch-1.6.0.zip` | repo1.maven.org/maven2/org/elasticsearch/elasticsearch/1.6.0 | `scenario-09-elasticsearch/` |
| `vc_redist.x64.exe` | aka.ms/vs/17/release/vc_redist.x64.exe | `scenario-15-wamp-wordpress/` |
| `php-7.4.33-nts-Win32-vc15-x64.zip` | windows.php.net/downloads/releases/archives | `scenario-15-wamp-wordpress/` |
| `mariadb-10.1.48-winx64.zip` | archive.mariadb.org/mariadb-10.1.48/winx64-packages | `scenario-15-wamp-wordpress/` |
| `wordpress-4.7.1.zip` | wordpress.org | `scenario-15-wamp-wordpress/` |
| `python-3.11.9-embed-amd64.zip` | python.org/ftp/python/3.11.9 | `scenario-01-snmp/` |
| `get-pip.py` | bootstrap.pypa.io | `scenario-01-snmp/` |
| `ManageEngine_DesktopCentral.exe` | metasploitable-binaries.s3.amazonaws.com (Rapid7 mirror of DC 9.1.0_91097) | `scenario-16-manageengine/` |
