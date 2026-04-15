# syntax=docker/dockerfile:1
# meta3-win-06-jenkins — Jenkins 2.32.1 with CLI remoting deserialization (CVE-2017-1000353)
# Upstream: scripts/installs/setup_jenkins.bat (copies jenkins.war + jenkins.exe service wrapper)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- JRE 8 ---
ARG TEMURIN_URL=https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u402-b06/OpenJDK8U-jre_x64_windows_hotspot_8u402b06.zip
RUN Invoke-WebRequest -Uri $env:TEMURIN_URL -OutFile 'C:\jre.zip' ; \
    Expand-Archive 'C:\jre.zip' -DestinationPath 'C:\Java' ; \
    Remove-Item 'C:\jre.zip'
ENV JAVA_HOME=C:\\Java\\jdk8u402-b06-jre
ENV PATH=C:\\Java\\jdk8u402-b06-jre\\bin;${PATH}

# --- Jenkins 2.32.1 WAR (vulnerable to CVE-2017-1000353 pre-auth CLI RCE) ---
ARG JENKINS_URL=https://archives.jenkins.io/war/2.32.1/jenkins.war
RUN New-Item -ItemType Directory -Path 'C:\jenkins' -Force | Out-Null ; \
    Invoke-WebRequest -Uri $env:JENKINS_URL -OutFile 'C:\jenkins\jenkins.war'

# --- Pre-seeded JENKINS_HOME with security disabled (useSecurity=false) ---
ENV JENKINS_HOME=C:\\jenkins\\home
COPY jenkins_home/ C:/jenkins/home/

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 8080 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; & java -Djenkins.install.runSetupWizard=false -DJENKINS_HOME=C:\\jenkins\\home -jar C:\\jenkins\\jenkins.war --httpPort=8080"]
