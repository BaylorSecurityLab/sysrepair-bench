# syntax=docker/dockerfile:1
# meta3-win-09-elasticsearch — Elasticsearch 1.6.0 with Groovy sandbox bypass enabled (CVE-2015-1427)
# ES 1.1.1 (the upstream Rapid7 pin) crashes on Server Core ltsc2019 under every
# tested JRE; 1.6.0 targets the same RCE class (/_search script injection) and
# actually boots. 1.6.0 ships dynamic scripting disabled by default but still allows
# sandboxed Groovy, and the sandbox can be bypassed per CVE-2015-1427 — we also
# explicitly disable the sandbox in elasticsearch.yml to keep the PoC one-shot.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- JRE 8 (8u312 is the last build before ES 1.x's Lucene JNI bits go sideways) ---
ARG TEMURIN_URL=https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u312-b07/OpenJDK8U-jre_x64_windows_hotspot_8u312b07.zip
RUN Invoke-WebRequest -Uri $env:TEMURIN_URL -OutFile 'C:\jre.zip' ; \
    Expand-Archive 'C:\jre.zip' -DestinationPath 'C:\Java' ; \
    Remove-Item 'C:\jre.zip'
ENV JAVA_HOME=C:\\Java\\jdk8u312-b07-jre

# --- Elasticsearch 1.6.0 ---
ARG ES_URL=https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-1.6.0.zip
RUN Invoke-WebRequest -Uri $env:ES_URL -OutFile 'C:\es.zip' ; \
    Expand-Archive 'C:\es.zip' -DestinationPath 'C:\' ; \
    Remove-Item 'C:\es.zip' ; \
    Remove-Item 'C:\elasticsearch-1.6.0\lib\sigar\sigar-amd64-winnt.dll' -Force ; \
    Remove-Item 'C:\elasticsearch-1.6.0\lib\sigar\sigar-x86-winnt.dll' -Force
ENV ES_HOME=C:\\elasticsearch-1.6.0
# Sigar's bundled Windows DLL crashes the JVM with EXCEPTION_ACCESS_VIOLATION inside
# Server Core ltsc2019 containers. Deleting the native library forces Sigar into its
# Java-only fallback (System.loadLibrary throws UnsatisfiedLinkError, which ES catches
# and logs as a benign warning). Process-level stats are lost but the REST API works.

# Bind to all interfaces; enable dynamic scripting and disable the Groovy sandbox
# — both conditions reproduce the CVE-2015-1427 RCE surface.
COPY elasticsearch.yml C:/elasticsearch-1.6.0/config/elasticsearch.yml

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 9200 9300 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; & C:\\elasticsearch-1.6.0\\bin\\elasticsearch.bat"]
