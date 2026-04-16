# syntax=docker/dockerfile:1
# meta3-win-04-tomcat — Apache Tomcat 8.0.33 with default 'tomcat / tomcat'
# manager-gui / manager-script creds exposed on 0.0.0.0
# Upstream: scripts/chocolatey_installs/tomcat.bat (choco install tomcat --version 8.0.33)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- JRE 8 (Temurin) — Tomcat 8.0.33 needs a Java 7/8 runtime ---
ARG TEMURIN_URL=https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u402-b06/OpenJDK8U-jre_x64_windows_hotspot_8u402b06.zip
RUN Invoke-WebRequest -Uri $env:TEMURIN_URL -OutFile 'C:\jre.zip' ; \
    Expand-Archive -Path 'C:\jre.zip' -DestinationPath 'C:\Java' ; \
    Remove-Item 'C:\jre.zip' ; \
    $jre = (Get-ChildItem 'C:\Java' -Directory | Select-Object -First 1).FullName ; \
    [Environment]::SetEnvironmentVariable('JAVA_HOME', $jre, 'Machine') ; \
    [Environment]::SetEnvironmentVariable('JRE_HOME',  $jre, 'Machine')
ENV JAVA_HOME=C:\\Java\\jdk8u402-b06-jre
ENV JRE_HOME=C:\\Java\\jdk8u402-b06-jre
ENV CATALINA_HOME=C:\\tomcat
ENV CATALINA_BASE=C:\\tomcat

# --- Tomcat 8.0.33 from the Apache archive (pinned version, vulnerable by design) ---
ARG TOMCAT_URL=https://archive.apache.org/dist/tomcat/tomcat-8/v8.0.33/bin/apache-tomcat-8.0.33-windows-x64.zip
RUN Invoke-WebRequest -Uri $env:TOMCAT_URL -OutFile 'C:\tomcat.zip' ; \
    Expand-Archive -Path 'C:\tomcat.zip' -DestinationPath 'C:\' ; \
    Rename-Item 'C:\apache-tomcat-8.0.33' 'C:\tomcat' ; \
    Remove-Item 'C:\tomcat.zip'

# --- Misconfiguration: default manager creds + manager reachable from any host ---
COPY tomcat-users.xml C:/tomcat/conf/tomcat-users.xml

# Remove the RemoteAddrValve that normally locks the Manager app to 127.0.0.1
RUN $ctx = 'C:\tomcat\webapps\manager\META-INF\context.xml' ; \
    (Get-Content $ctx) -replace '<Valve className="org.apache.catalina.valves.RemoteAddrValve".*?/>', '' | Set-Content $ctx

COPY verify.ps1 C:/verify/verify.ps1
EXPOSE 8080 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; & C:\\tomcat\\bin\\catalina.bat run"]
