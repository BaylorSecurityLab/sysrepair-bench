# syntax=docker/dockerfile:1
# meta3-win-09-elasticsearch — Elasticsearch 1.1.1 with dynamic scripting enabled (CVE-2014-3120)
# Upstream: scripts/installs/install_elasticsearch.bat
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- JRE 8 (ES 1.1.1 shipped for JRE 7 but runs on 8) ---
ARG TEMURIN_URL=https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u402-b06/OpenJDK8U-jre_x64_windows_hotspot_8u402b06.zip
RUN Invoke-WebRequest -Uri $env:TEMURIN_URL -OutFile 'C:\jre.zip' ; \
    Expand-Archive 'C:\jre.zip' -DestinationPath 'C:\Java' ; \
    Remove-Item 'C:\jre.zip'
ENV JAVA_HOME=C:\\Java\\jdk8u402-b06-jre

# --- Elasticsearch 1.1.1 ---
ARG ES_URL=https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-1.1.1.zip
RUN Invoke-WebRequest -Uri $env:ES_URL -OutFile 'C:\es.zip' ; \
    Expand-Archive 'C:\es.zip' -DestinationPath 'C:\' ; \
    Remove-Item 'C:\es.zip'
ENV ES_HOME=C:\\elasticsearch-1.1.1

# Bind to all interfaces so the port-map can reach it; leave script.disable_dynamic
# at its default (false) — that is the CVE-2014-3120 condition.
RUN $cfg = "$env:ES_HOME\config\elasticsearch.yml" ; \
    Add-Content $cfg "`nnetwork.host: 0.0.0.0`n" ; \
    Add-Content $cfg "http.port: 9200`n" ; \
    Add-Content $cfg "cluster.name: meta3-es`n"

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 9200 9300 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; & C:\\elasticsearch-1.1.1\\bin\\elasticsearch.bat"]
