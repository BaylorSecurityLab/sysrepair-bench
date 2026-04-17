# syntax=docker/dockerfile:1
# meta3-win-09-elasticsearch — Elasticsearch 1.1.1 with dynamic scripting enabled (CVE-2014-3120)
# Upstream: scripts/installs/install_elasticsearch.bat
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- JRE 8 (ES 1.1.1 shipped for JRE 7 but runs on 8) ---
# ES 1.1.1 (Lucene 4.6) crashes with JRE 8u402 native code; 8u312 is stable.
ARG TEMURIN_URL=https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u312-b07/OpenJDK8U-jre_x64_windows_hotspot_8u312b07.zip
RUN Invoke-WebRequest -Uri $env:TEMURIN_URL -OutFile 'C:\jre.zip' ; \
    Expand-Archive 'C:\jre.zip' -DestinationPath 'C:\Java' ; \
    Remove-Item 'C:\jre.zip'
ENV JAVA_HOME=C:\\Java\\jdk8u312-b07-jre

# --- Elasticsearch 1.1.1 ---
ARG ES_URL=https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-1.1.1.zip
RUN Invoke-WebRequest -Uri $env:ES_URL -OutFile 'C:\es.zip' ; \
    Expand-Archive 'C:\es.zip' -DestinationPath 'C:\' ; \
    Remove-Item 'C:\es.zip'
ENV ES_HOME=C:\\elasticsearch-1.1.1

# Bind to all interfaces so the port-map can reach it; explicitly enable dynamic
# scripting — that is the CVE-2014-3120 condition.
COPY elasticsearch.yml C:/elasticsearch-1.1.1/config/elasticsearch.yml

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 9200 9300 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; & C:\\elasticsearch-1.1.1\\bin\\elasticsearch.bat"]
