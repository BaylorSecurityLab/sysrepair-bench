# syntax=docker/dockerfile:1
# meta3-win-08-axis2 — Apache Axis2 1.6.0 on Tomcat with default admin/axis2 creds
# Upstream: scripts/installs/setup_axis2.bat (downloads axis2-1.6.0-war.zip, drops axis2.war in Tomcat)
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

# --- Axis2 1.6.0 WAR (ships with admin/axis2 default creds in WEB-INF/conf/axis2.xml) ---
ARG AXIS2_URL=https://archive.apache.org/dist/axis/axis2/java/core/1.6.0/axis2-1.6.0-war.zip
RUN Invoke-WebRequest -Uri $env:AXIS2_URL -OutFile 'C:\axis2.zip' ; \
    Expand-Archive 'C:\axis2.zip' -DestinationPath 'C:\axis2' ; \
    Copy-Item 'C:\axis2\axis2.war' 'C:\tomcat\webapps\axis2.war' ; \
    Remove-Item -Recurse -Force 'C:\axis2','C:\axis2.zip'

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 8080 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; & C:\\tomcat\\bin\\catalina.bat run"]
