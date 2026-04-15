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

# Chocolatey bootstrap
RUN Set-ExecutionPolicy Bypass -Scope Process -Force ; \
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072 ; \
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# MariaDB + PHP 5.6 + Apache httpd (pinned versions match the WampServer 3.0.6 stack)
RUN choco install -y --no-progress mariadb --version=10.1.21 ; \
    choco install -y --no-progress php --version=5.6.30 ; \
    choco install -y --no-progress apache-httpd --version=2.4.25

# Wire PHP into Apache and enable WordPress-relevant extensions
RUN $httpdConf = 'C:\tools\Apache24\conf\httpd.conf' ; \
    Add-Content -Path $httpdConf -Value "`nLoadModule php5_module `"C:/tools/php56/php5apache2_4.dll`"" ; \
    Add-Content -Path $httpdConf -Value "AddHandler application/x-httpd-php .php" ; \
    Add-Content -Path $httpdConf -Value "PHPIniDir `"C:/tools/php56`"" ; \
    Add-Content -Path $httpdConf -Value "DocumentRoot `"C:/wamp/www`"" ; \
    Copy-Item 'C:\tools\php56\php.ini-production' 'C:\tools\php56\php.ini' -Force ; \
    (Get-Content 'C:\tools\php56\php.ini') -replace ';extension=mysqli','extension=mysqli' -replace ';extension=mbstring','extension=mbstring' | Set-Content 'C:\tools\php56\php.ini'

# WordPress 4.7.1 (matches upstream metasploitable3-windows)
RUN New-Item -ItemType Directory -Path 'C:\wamp\www' -Force | Out-Null ; \
    Invoke-WebRequest -Uri 'https://wordpress.org/wordpress-4.7.1.zip' -OutFile 'C:\wp.zip' -UseBasicParsing ; \
    Expand-Archive -Path 'C:\wp.zip' -DestinationPath 'C:\wamp\www' -Force ; \
    Remove-Item 'C:\wp.zip'

COPY wp-config.php C:/wamp/www/wordpress/wp-config.php
COPY init-wordpress.sql C:/init-wordpress.sql
COPY verify.ps1 C:/verify/verify.ps1

# Bootstrap: start MariaDB, seed the WordPress DB + weak admin:admin login, start Apache
RUN Start-Service mariadb ; \
    Start-Sleep -Seconds 8 ; \
    & 'C:\Program Files\MariaDB 10.1\bin\mysql.exe' -u root -e "SOURCE C:/init-wordpress.sql" ; \
    Stop-Service mariadb

EXPOSE 80 3306 22 5985
CMD ["powershell", "-NoProfile", "-Command", "Start-Service sshd; Start-Service WinRM; Start-Service mariadb; Start-Process -FilePath 'C:\\tools\\Apache24\\bin\\httpd.exe'; while ($true) { Start-Sleep 60 }"]
