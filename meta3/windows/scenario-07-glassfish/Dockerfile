# syntax=docker/dockerfile:1
# meta3-win-07-glassfish — GlassFish 4.1.1 with admin traversal + empty admin password
# (CVE-2017-1000028 arbitrary file read; admin listener plaintext on :4848)
# Upstream: scripts/installs/setup_glassfish.bat + resources/glassfish/{admin-keyfile,domain.xml}
#
# Pinned to 4.1.1 (CVE-2017-1000028's canonical vulnerable build) rather than 4.0:
# 4.1.1 is the reference target for the overlong-UTF-8 (%c0%ae) traversal on the
# admin-console /theme/META-INF/ resource that verify.ps1 probes.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- JDK 8 (GlassFish 4.1.1 runs on JDK 8) ---
# Source URL: https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u402-b06/OpenJDK8U-jdk_x64_windows_hotspot_8u402b06.zip
COPY shared/downloads/OpenJDK8U-jdk_x64_windows_hotspot_8u402b06.zip C:/jdk.zip
RUN Expand-Archive 'C:\jdk.zip' -DestinationPath 'C:\Java' ; \
    Remove-Item 'C:\jdk.zip'
ENV JAVA_HOME=C:\\Java\\jdk8u402-b06
ENV AS_JAVA=C:\\Java\\jdk8u402-b06
# Do not append to ${PATH} via ENV — Docker expansion yields an empty string on Windows
# and wipes C:\Windows\System32 from PATH, breaking powershell for subsequent RUN steps.
# GlassFish resolves java via AS_JAVA → JAVA_HOME. The domain launch process also needs
# java on PATH, so the entrypoint prepends it at runtime.

# --- GlassFish 4.1.1 ---
# Source URL: https://download.oracle.com/glassfish/4.1.1/release/glassfish-4.1.1.zip
COPY shared/downloads/glassfish-4.1.1.zip C:/gf.zip
RUN Expand-Archive 'C:\gf.zip' -DestinationPath 'C:\' ; \
    Remove-Item 'C:\gf.zip'
ENV GLASSFISH_HOME=C:\\glassfish4\\glassfish

# --- Ship the genuinely-vulnerable default state ---
# The stock domain1 admin-keyfile stores the SSHA256 hash of the *empty* password
# (admin;{SSHA256}nd85GyUoUi+...;asadmin), and secure-admin is DISABLED by
# default, so :4848 stays plaintext HTTP. That IS the vulnerable state and it is
# shipped as-is: `GET http://localhost:4848/management/domain` answers 200 with
# no credentials at all on this image, while a wrong password answers 401.
#
# This step used to overwrite the admin line with 'admin;;asadmin' -- a literally
# empty hash field -- so that the verifier's PoC could look for an empty field
# instead of testing the password. GlassFish's FileRealm cannot parse that line:
# `asadmin start-domain` died with
#     java.io.IOException: java.lang.IllegalArgumentException: No local string defined
# and domain1 NEVER STARTED. Measured on the built image: no java process, nothing
# listening on 4848 or 8080, server.log stopping at the launch record. The
# regression check (glassfish_http_8080) could therefore never pass on an
# untouched box, which makes joint_pass unreachable and the scenario unsolvable.
# Restoring the stock keyfile starts the domain (4848 + 8080 listening, HTTP 200);
# verify.ps1 now proves the empty password behaviourally instead.

COPY scenario-07-glassfish/entrypoint.ps1 C:/entrypoint.ps1

EXPOSE 4848 8080 22 5985
# PID 1 is a powershell idle loop; the domain is started as a detached child so that
# the solution's restart-domain cannot kill the container. Paired with .preserve-cmd
# so the harness boots this CMD instead of `sleep infinity`.
CMD ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\\entrypoint.ps1"]
