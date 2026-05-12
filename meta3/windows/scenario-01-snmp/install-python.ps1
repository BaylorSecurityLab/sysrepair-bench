# Install a portable Python 3.11 (embeddable distribution) + pip + pysnmp.
# Server Core ltsc2019 has no Python package and no Windows Store, so we use
# the embeddable zip directly. pysnmp is pure-Python; no compiler required.
#
# This script no longer fetches from the network — the Dockerfile pre-stages
# python-3.11.9-embed-amd64.zip and get-pip.py at C:\python.zip and
# C:\get-pip.py before invoking us. Upstream sources are documented in
# meta3/windows/shared/downloads/README.md.
$ErrorActionPreference = 'Stop'

$pyDir = 'C:\Python311'

New-Item -ItemType Directory -Force -Path $pyDir | Out-Null
Expand-Archive -Path 'C:\python.zip' -DestinationPath $pyDir -Force
Remove-Item 'C:\python.zip'

# The embeddable distribution ships with a ._pth file that disables site-packages.
# Uncomment `import site` so pip-installed packages are importable.
$pth = Get-ChildItem "$pyDir\python*._pth" | Select-Object -First 1
(Get-Content $pth.FullName) -replace '^#\s*import site', 'import site' | Set-Content $pth.FullName

# pip needs to be installable offline too. pysnmp/pyasn1 are still pulled from
# PyPI at build time — those wheels are small (<200KB combined) and a fail
# there is loud and obvious, so we don't pre-stage them.
& "$pyDir\python.exe" 'C:\get-pip.py' --no-warn-script-location
Remove-Item 'C:\get-pip.py'

& "$pyDir\python.exe" -m pip install --no-warn-script-location pysnmp==4.4.12 pyasn1==0.4.8
