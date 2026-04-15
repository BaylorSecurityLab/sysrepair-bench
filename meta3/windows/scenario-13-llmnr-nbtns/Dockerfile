# syntax=docker/dockerfile:1
# meta3-win-13-llmnr-nbtns — LLMNR + NBT-NS broadcast name resolution enabled (Responder bait)
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Ensure LLMNR is ON (absence or 1 = on) and NBT-NS is enabled on every interface.
# Group Policy key: HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast
#   - value 0 disables LLMNR; deleting the key or setting 1 leaves it on.
# NetBT per-interface: NetbiosOptions under Tcpip\Parameters\Interfaces\{GUID}
#   - 0 = default (use DHCP), 1 = enabled, 2 = disabled.
RUN New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null ; \
    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 1 -Type DWord ; \
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { \
        Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 1 -Type DWord \
    }

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; while ($true) { Start-Sleep 60 }"]
