# syntax=docker/dockerfile:1
# meta3-win-06-jenkins — Jenkins 2.32.1 with CLI remoting deserialization (CVE-2017-1000353)
# Upstream: scripts/installs/setup_jenkins.bat (copies jenkins.war + jenkins.exe service wrapper)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- JRE 8 ---
# Source URL: https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u402-b06/OpenJDK8U-jre_x64_windows_hotspot_8u402b06.zip
COPY shared/downloads/OpenJDK8U-jre_x64_windows_hotspot_8u402b06.zip C:/jre.zip
RUN Expand-Archive 'C:\jre.zip' -DestinationPath 'C:\Java' ; \
    Remove-Item 'C:\jre.zip'
ENV JAVA_HOME=C:\\Java\\jdk8u402-b06-jre
# Do not use ${PATH} expansion in ENV here — Docker resolves it against earlier ENV directives
# only, which produces an empty string and wipes Windows\System32 from PATH on subsequent RUN
# steps, breaking powershell.exe lookup. Use the fully-qualified java.exe in the entrypoint.

# --- Jenkins 2.32.1 WAR (the running, vulnerable CVE-2017-1000353 instance) ---
# archives.jenkins.io dropped the 2.32.x weekly WARs; the Artifactory mirror still serves them.
# Source URL: https://repo.jenkins-ci.org/public/org/jenkins-ci/main/jenkins-war/2.32.1/jenkins-war-2.32.1.war
RUN New-Item -ItemType Directory -Path 'C:\jenkins' -Force | Out-Null
COPY shared/downloads/jenkins-war-2.32.1.war C:/jenkins/jenkins.war

# --- Staged FIXED Jenkins WAR (2.60.3, first LTS past the 2.46.2 remoting fix) ---
# Not active in the baseline — the solution copies it over jenkins.war so the whole
# vulnerable->remediated path is HERMETIC (no runtime network egress needed).
# Source URL: https://get.jenkins.io/war-stable/2.60.3/jenkins.war
COPY shared/downloads/jenkins-2.60.3.war C:/jenkins/jenkins-fixed.war

# --- Pre-seeded JENKINS_HOME with security disabled (useSecurity=false) ---
ENV JENKINS_HOME=C:\\jenkins\\home
COPY scenario-06-jenkins/jenkins_home/ C:/jenkins/home/

COPY scenario-06-jenkins/entrypoint.ps1 C:/entrypoint.ps1

EXPOSE 8080 22 5985
# PID 1 is a powershell idle loop; Jenkins runs as a detached child so the solution can
# stop/replace/restart the java process without killing the container. Paired with
# .preserve-cmd so the harness boots this CMD instead of `sleep infinity`.
CMD ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\\entrypoint.ps1"]
