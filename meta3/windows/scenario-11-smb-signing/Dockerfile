# syntax=docker/dockerfile:1
# meta3-win-11-smb-signing — SMB signing not required (NTLM relay surface)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Disable required + enabled signing on server and client sides so a downgrade negotiates
# an unsigned session — the classic precondition for NTLM relay (responder + ntlmrelayx).
RUN Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force ; \
    Set-SmbClientConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force ; \
    New-NetFirewallRule -DisplayName 'SMB-445' -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 445 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service LanmanServer; while ($true) { Start-Sleep 60 }"]
