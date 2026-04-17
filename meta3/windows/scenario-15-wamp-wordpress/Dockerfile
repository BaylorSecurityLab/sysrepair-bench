# syntax=docker/dockerfile:1
# meta3-win-15-wamp-wordpress — WAMP (Apache + MariaDB + PHP) hosting WordPress 4.7.1 with weak admin creds
#
# Upstream Rapid7 metasploitable3 installs WampServer 3.0.6 + WordPress 4.7.1 via a NSIS
# silent installer that repeatedly hangs on Server Core. We replicate the vulnerable
# surface without WampServer itself by pulling pinned Apache Lounge + PHP 5.6 + MariaDB
# from Chocolatey, then dropping the same WordPress 4.7.1 tree with the weak
# admin:admin credentials Rapid7 ships.
FROM sysrepair/meta3-win-base:ltsc2019

SHELL ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "$ErrorActionPreference='Stop';"]

# Install VCRT 2015-2022 (required by PHP)
RUN Invoke-WebRequest -Uri 'https://aka.ms/vs/17/release/vc_redist.x64.exe' -OutFile 'C:\vc.exe' -UseBasicParsing ; \
    Start-Process -FilePath 'C:\vc.exe' -ArgumentList '/install','/quiet','/norestart' -Wait ; \
    Remove-Item 'C:\vc.exe'

# IIS + CGI (replaces Apache — Apache Lounge downloads are blocked from containers)
RUN dism /online /enable-feature /all /NoRestart \
        /featurename:IIS-WebServerRole /featurename:IIS-WebServer \
        /featurename:IIS-CommonHttpFeatures /featurename:IIS-DefaultDocument \
        /featurename:IIS-StaticContent /featurename:IIS-CGI \
        /featurename:IIS-ISAPIExtensions /featurename:IIS-ISAPIFilter \
        /featurename:IIS-ManagementScriptingTools ; exit 0

# PHP 7.4.33 NTS (FastCGI for IIS)
RUN Invoke-WebRequest -Uri 'https://windows.php.net/downloads/releases/archives/php-7.4.33-nts-Win32-vc15-x64.zip' -OutFile 'C:\php.zip' -UseBasicParsing ; \
    Expand-Archive 'C:\php.zip' -DestinationPath 'C:\php' -Force ; \
    Remove-Item 'C:\php.zip' ; \
    Copy-Item 'C:\php\php.ini-production' 'C:\php\php.ini' -Force ; \
    (Get-Content 'C:\php\php.ini') -replace ';extension=mysqli','extension=mysqli' -replace ';extension=mbstring','extension=mbstring' | Set-Content 'C:\php\php.ini'

# MariaDB 10.1.21 (zip distribution — no installer needed)
RUN Invoke-WebRequest -Uri 'https://archive.mariadb.org/mariadb-10.1.21/winx64-packages/mariadb-10.1.21-winx64.zip' -OutFile 'C:\mariadb.zip' -UseBasicParsing ; \
    Expand-Archive 'C:\mariadb.zip' -DestinationPath 'C:\' -Force ; \
    Rename-Item 'C:\mariadb-10.1.21-winx64' 'C:\mariadb' ; \
    Remove-Item 'C:\mariadb.zip' ; \
    & 'C:\mariadb\bin\mysql_install_db.exe' --datadir='C:\mariadb\data' --service='mariadb'

# Wire PHP into IIS via FastCGI and set document root
RUN Import-Module WebAdministration ; \
    New-WebHandler -Name 'PHP-FastCGI' -Path '*.php' -Verb '*' -Modules 'FastCgiModule' -ScriptProcessor 'C:\php\php-cgi.exe' -ResourceType File ; \
    Add-WebConfiguration -Filter '/system.webServer/fastCgi' -PSPath 'IIS:\' -Value @{fullPath='C:\php\php-cgi.exe'} ; \
    Set-ItemProperty 'IIS:\Sites\Default Web Site' -Name physicalPath -Value 'C:\wamp\www\wordpress'

# WordPress 4.7.1 (matches upstream metasploitable3-windows)
RUN New-Item -ItemType Directory -Path 'C:\wamp\www' -Force | Out-Null ; \
    Invoke-WebRequest -Uri 'https://wordpress.org/wordpress-4.7.1.zip' -OutFile 'C:\wp.zip' -UseBasicParsing ; \
    Expand-Archive -Path 'C:\wp.zip' -DestinationPath 'C:\wamp\www' -Force ; \
    Remove-Item 'C:\wp.zip'

COPY wp-config.php C:/wamp/www/wordpress/wp-config.php
COPY init-wordpress.sql C:/init-wordpress.sql
COPY verify.ps1 C:/verify/verify.ps1

# Bootstrap: start MariaDB, seed the WordPress DB + weak admin:admin login
RUN Start-Service mariadb ; \
    Start-Sleep -Seconds 8 ; \
    cmd /c 'C:\mariadb\bin\mysql.exe -u root < C:\init-wordpress.sql' ; \
    Stop-Service mariadb

EXPOSE 80 3306 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service mariadb; Start-Service W3SVC; while ($true) { Start-Sleep 60 }"]
