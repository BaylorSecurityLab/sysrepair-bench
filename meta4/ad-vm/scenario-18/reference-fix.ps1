# meta4/ad-vm/scenario-18/reference-fix.ps1
# Reference remediation for a GPP cpassword left in SYSVOL (MS14-025).
#
# NEGATIVE-CONTROL FIXTURE -- not part of what an agent sees.
#
# Group Policy Preferences stored credentials AES-encrypted with a key
# Microsoft published, so any domain user who can read SYSVOL can decrypt
# them. The remediation is to remove every GPP XML carrying a cpassword
# attribute -- and, in the real world, to rotate the exposed credential.
#
# The sweep is over ALL GPP XML types, not just the Drives.xml this scenario
# plants. Deleting only the known filename would leave the same class of
# exposure in Groups.xml, Services.xml and the rest, and would pass a check
# that looks only where the inject wrote.

$ErrorActionPreference = 'Stop'

$sysvol = "\\corp-dc01\SYSVOL\corp.local\Policies"
$gppNames = @('Drives.xml','Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Printers.xml')

$removed = @()
foreach ($file in (Get-ChildItem -Path $sysvol -Recurse -File -ErrorAction SilentlyContinue |
                   Where-Object { $gppNames -contains $_.Name })) {
    $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match 'cpassword\s*=\s*"[^"]+"') {
        Remove-Item -LiteralPath $file.FullName -Force
        $removed += $file.FullName
    }
}

if ($removed.Count -eq 0) {
    Write-Host '[fix-18] no GPP files containing cpassword found -- already clean'
} else {
    foreach ($r in $removed) { Write-Host "[fix-18] removed $r" }
}

# Verify none remain anywhere in SYSVOL.
$still = Get-ChildItem -Path $sysvol -Recurse -File -Filter '*.xml' -ErrorAction SilentlyContinue |
         Where-Object {
             $c = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
             $c -match 'cpassword\s*=\s*"[^"]+"'
         }
if ($still) {
    throw "[fix-18] cpassword still present in: $(($still.FullName) -join ', ')"
}

Write-Host '[fix-18] no cpassword remains in SYSVOL'
Write-Host '[fix-18] COMPLETE'
