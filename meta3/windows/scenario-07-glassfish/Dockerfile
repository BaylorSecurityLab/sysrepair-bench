# syntax=docker/dockerfile:1
# meta3-win-07-glassfish — GlassFish 4.0 with admin traversal + weak admin realm
# (CVE-2017-1000028 arbitrary file read; admin listener reachable on all interfaces)
# Upstream: scripts/installs/setup_glassfish.bat + resources/glassfish/{admin-keyfile,domain.xml}
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# --- JDK 8 (GlassFish 4.0 was released for JDK7 but runs on 8 with warnings) ---
ARG TEMURIN_URL=https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u402-b06/OpenJDK8U-jdk_x64_windows_hotspot_8u402b06.zip
RUN Invoke-WebRequest -Uri $env:TEMURIN_URL -OutFile 'C:\jdk.zip' ; \
    Expand-Archive 'C:\jdk.zip' -DestinationPath 'C:\Java' ; \
    Remove-Item 'C:\jdk.zip'
ENV JAVA_HOME=C:\\Java\\jdk8u402-b06
ENV AS_JAVA=C:\\Java\\jdk8u402-b06
# Do not append to ${PATH} via ENV — Docker expansion yields an empty string on Windows
# and wipes C:\Windows\System32 from PATH, breaking powershell for subsequent RUN steps.
# GlassFish resolves java via AS_JAVA → JAVA_HOME. The domain launch process also needs
# java on PATH, so the CMD prepends it at runtime.

# --- GlassFish 4.0 ---
ARG GLASSFISH_URL=https://download.oracle.com/glassfish/4.0/release/glassfish-4.0.zip
RUN Invoke-WebRequest -Uri $env:GLASSFISH_URL -OutFile 'C:\gf.zip' ; \
    Expand-Archive 'C:\gf.zip' -DestinationPath 'C:\' ; \
    Remove-Item 'C:\gf.zip'
ENV GLASSFISH_HOME=C:\\glassfish4\\glassfish

# --- Misconfiguration: enable secure admin with an empty admin password ---
# GlassFish 4.0 enable-secure-admin refuses to run when any admin account has an
# empty password. Workaround: set a temp password, enable-secure-admin, then change
# back to empty. The domain restart (in CMD) is what activates the 0.0.0.0 binding.
RUN & "$env:GLASSFISH_HOME\bin\asadmin.bat" --user admin start-domain domain1 ; \
    Start-Sleep -Seconds 10 ; \
    Set-Content -Path 'C:\pf_empty'    -Value 'AS_ADMIN_PASSWORD=' -Encoding ASCII ; \
    Set-Content -Path 'C:\pf_temp'     -Value 'AS_ADMIN_PASSWORD=TempAdmin1!' -Encoding ASCII ; \
    Set-Content -Path 'C:\pf_to_temp'  -Value "AS_ADMIN_PASSWORD=`nAS_ADMIN_NEWPASSWORD=TempAdmin1!" -Encoding ASCII ; \
    Set-Content -Path 'C:\pf_to_empty' -Value "AS_ADMIN_PASSWORD=TempAdmin1!`nAS_ADMIN_NEWPASSWORD=" -Encoding ASCII ; \
    & "$env:GLASSFISH_HOME\bin\asadmin.bat" --user admin --passwordfile 'C:\pf_to_temp'  change-admin-password ; \
    & "$env:GLASSFISH_HOME\bin\asadmin.bat" --user admin --passwordfile 'C:\pf_temp'     enable-secure-admin ; \
    & "$env:GLASSFISH_HOME\bin\asadmin.bat" --user admin --passwordfile 'C:\pf_to_empty' change-admin-password ; \
    & "$env:GLASSFISH_HOME\bin\asadmin.bat" --user admin --passwordfile 'C:\pf_empty'    stop-domain domain1 ; \
    Remove-Item 'C:\pf_empty', 'C:\pf_temp', 'C:\pf_to_temp', 'C:\pf_to_empty'


EXPOSE 4848 8080 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; $env:Path = 'C:\\Java\\jdk8u402-b06\\bin;' + $env:Path; & C:\\glassfish4\\glassfish\\bin\\asadmin.bat start-domain --verbose domain1"]
