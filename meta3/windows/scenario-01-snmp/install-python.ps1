# Install a portable Python 3.11 (embeddable distribution) + pip + pysnmp.
# Server Core ltsc2019 has no Python package and no Windows Store, so we pull
# the embeddable zip directly. pysnmp is pure-Python; no compiler required.
$ErrorActionPreference = 'Stop'

$pyUrl  = 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip'
$pyDir  = 'C:\Python311'
$pipUrl = 'https://bootstrap.pypa.io/get-pip.py'

New-Item -ItemType Directory -Force -Path $pyDir | Out-Null
Invoke-WebRequest -Uri $pyUrl -OutFile 'C:\python.zip' -UseBasicParsing
Expand-Archive -Path 'C:\python.zip' -DestinationPath $pyDir -Force
Remove-Item 'C:\python.zip'

# The embeddable distribution ships with a ._pth file that disables site-packages.
# Uncomment `import site` so pip-installed packages are importable.
$pth = Get-ChildItem "$pyDir\python*._pth" | Select-Object -First 1
(Get-Content $pth.FullName) -replace '^#\s*import site', 'import site' | Set-Content $pth.FullName

Invoke-WebRequest -Uri $pipUrl -OutFile "$pyDir\get-pip.py" -UseBasicParsing
& "$pyDir\python.exe" "$pyDir\get-pip.py" --no-warn-script-location
Remove-Item "$pyDir\get-pip.py"

& "$pyDir\python.exe" -m pip install --no-warn-script-location pysnmp==4.4.12 pyasn1==0.4.8
