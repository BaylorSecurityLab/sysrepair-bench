# meta4/ad-vm/scenario-11/reference-fix.ps1
# Reference remediation for ADCS ESC8 (Web Enrollment relay surface).
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# KNOWN SCENARIO DEFECT, recorded rather than worked around:
# threat.md lists three remediations, one of which is enabling Extended
# Protection for Authentication (tokenChecking=Require). verify-poc.sh decides
# purely on whether /certsrv answers HTTP 200 with the enrollment banner, and
# EPA does not change that -- an EPA-hardened endpoint still returns 200. So a
# correct EPA fix is graded as a failure. The scenario should be reworked to
# attempt an actual relay; until then only removal-style fixes can pass.
#
# This fixture uninstalls Web Enrollment, which is the strongest of the three
# documented remediations and the one the PoC can actually observe: /certsrv
# stops existing, so the request 404s or refuses.

$ErrorActionPreference = 'Stop'

if ((Get-WindowsFeature -Name ADCS-Web-Enrollment).Installed) {
    # Remove the role service; this also removes the /certsrv application.
    Uninstall-AdcsWebEnrollment -Force -ErrorAction SilentlyContinue | Out-Null
    Uninstall-WindowsFeature ADCS-Web-Enrollment -ErrorAction Stop | Out-Null
    Write-Host '[fix-11] ADCS Web Enrollment role service removed'
} else {
    Write-Host '[fix-11] ADCS Web Enrollment already absent'
}

# IIS may still be serving a stale application until it reloads.
& iisreset /restart 2>&1 | Out-Null

if ((Get-WindowsFeature -Name ADCS-Web-Enrollment).Installed) {
    throw '[fix-11] ADCS-Web-Enrollment is still installed'
}

Write-Host '[fix-11] /certsrv relay surface removed'
Write-Host '[fix-11] COMPLETE'
