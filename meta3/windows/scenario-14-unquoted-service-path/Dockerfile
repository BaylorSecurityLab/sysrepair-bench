# syntax=docker/dockerfile:1
# meta3-win-14-unquoted-service-path — service with unquoted ImagePath + writable parent dir (priv-esc)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Plant a vulnerable service:
#   - Install path: C:\Program Files\Meta Vuln\bin\vulnsvc.exe  (note the space in "Meta Vuln")
#   - Registered ImagePath is UNQUOTED, so SCM tries:
#       C:\Program.exe
#       C:\Program Files\Meta.exe
#       C:\Program Files\Meta Vuln\bin\vulnsvc.exe
#   - ACL on C:\Program Files\Meta Vuln grants BUILTIN\Users Modify, so a low-priv
#     user can drop C:\Program Files\Meta.exe and win the race at next service start.
RUN New-Item -ItemType Directory -Path 'C:\Program Files\Meta Vuln\bin' -Force | Out-Null ; \
    Set-Content -Path 'C:\Program Files\Meta Vuln\bin\vulnsvc.exe' -Value 'stub' -Encoding ASCII -Force ; \
    icacls 'C:\Program Files\Meta Vuln' /grant 'BUILTIN\Users:(OI)(CI)M' /T ; \
    New-Service -Name 'MetaVulnSvc' -DisplayName 'Meta Vuln Service' -BinaryPathName 'C:\Program Files\Meta Vuln\bin\vulnsvc.exe --run' -StartupType Manual


# The entrypoint normalizes the drive-root DACL before starting anything. It has
# to happen at BOOT, not in a RUN: the Windows container runtime re-establishes
# the security descriptor of the volume root when the container filesystem is
# mounted, so a build-time change to C:\ is discarded. See entrypoint.ps1 for
# the measurement and for what is being normalized and why.
COPY scenario-14-unquoted-service-path/entrypoint.ps1 C:/entrypoint.ps1

EXPOSE 22 5985
CMD ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\\entrypoint.ps1"]
