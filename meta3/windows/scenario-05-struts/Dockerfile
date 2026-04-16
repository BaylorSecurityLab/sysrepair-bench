# syntax=docker/dockerfile:1
# meta3-win-05-struts — Apache Struts 2 REST Showcase on Tomcat (CVE-2017-5638 / S2-045)
# Upstream: scripts/installs/setup_apache_struts.bat (deploys struts2-rest-showcase.war onto Tomcat 8.0.33)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- JRE 8 ---
ARG TEMURIN_URL=https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u402-b06/OpenJDK8U-jre_x64_windows_hotspot_8u402b06.zip
RUN Invoke-WebRequest -Uri $env:TEMURIN_URL -OutFile 'C:\jre.zip' ; \
    Expand-Archive 'C:\jre.zip' -DestinationPath 'C:\Java' ; \
    Remove-Item 'C:\jre.zip'
ENV JAVA_HOME=C:\\Java\\jdk8u402-b06-jre
ENV JRE_HOME=C:\\Java\\jdk8u402-b06-jre

# --- Tomcat 8.0.33 ---
ARG TOMCAT_URL=https://archive.apache.org/dist/tomcat/tomcat-8/v8.0.33/bin/apache-tomcat-8.0.33-windows-x64.zip
RUN Invoke-WebRequest -Uri $env:TOMCAT_URL -OutFile 'C:\tomcat.zip' ; \
    Expand-Archive 'C:\tomcat.zip' -DestinationPath 'C:\' ; \
    Rename-Item 'C:\apache-tomcat-8.0.33' 'C:\tomcat' ; \
    Remove-Item 'C:\tomcat.zip'
ENV CATALINA_HOME=C:\\tomcat
ENV CATALINA_BASE=C:\\tomcat

# --- Vulnerable Struts 2 REST Showcase WAR (2.3.20.1 is affected by S2-045) ---
# archive.apache.org pruned 2.3.15.1; 2.3.20.1 is the oldest still-published release
# in the vulnerable range (Struts 2.3.5–2.3.31 / 2.5–2.5.10 are affected by CVE-2017-5638).
ARG STRUTS_VERSION=2.3.20.1
ARG STRUTS_URL=https://archive.apache.org/dist/struts/2.3.20.1/struts-2.3.20.1-apps.zip
RUN Invoke-WebRequest -Uri $env:STRUTS_URL -OutFile 'C:\struts.zip' ; \
    Expand-Archive 'C:\struts.zip' -DestinationPath 'C:\struts-apps' ; \
    Copy-Item \"C:\\struts-apps\\struts-$env:STRUTS_VERSION\\apps\\struts2-rest-showcase.war\" 'C:\tomcat\webapps\struts2-rest-showcase.war' ; \
    Remove-Item -Recurse -Force 'C:\struts-apps','C:\struts.zip'

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 8080 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; & C:\\tomcat\\bin\\catalina.bat run"]
