# syntax=docker/dockerfile:1
# meta3-win-01-snmp — SNMP agent with 'public' community string (READ-WRITE)
#
# Upstream metasploitable3-windows uses Windows' built-in SNMP service. On
# Server Core ltsc2019 that capability has been stripped from the component
# store ("Disabled with Payload Removed"), so Add-WindowsCapability / DISM
# cannot reach it inside a container. We stand in a pure-Python SNMPv2c agent
# (pysnmp) that exposes the same vulnerable shape: UDP/161 listening, the
# 'public' community with READ-WRITE permissions, and no authentication traps.
# The service is still attackable with snmp-check / snmpwalk / snmpset.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

COPY install-python.ps1 C:/install-python.ps1
RUN powershell -NoProfile -ExecutionPolicy Bypass -File C:\install-python.ps1 ; \
    Remove-Item C:\install-python.ps1

COPY snmp_agent.py C:/snmp/snmp_agent.py
COPY snmp_probe.py C:/snmp/snmp_probe.py
COPY entrypoint.ps1 C:/entrypoint.ps1

EXPOSE 161/udp 22 5985
CMD ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\\entrypoint.ps1"]
