# Scenario 14 entrypoint.
#
# Normalizes the drive-root DACL to desktop-Windows parity, then boots the
# scenario's services and idles as PID 1.
#
# WHY THIS RUNS AT BOOT AND NOT IN THE DOCKERFILE. It was written as a build
# time RUN first. It does not survive. MEASURED: the build layer really does
# apply it -- `icacls C:\` at the end of the RUN prints
# `NT AUTHORITY\Authenticated Users:(AD)` -- but
#     docker run --rm <image> icacls C:\
# on the resulting image prints `NT AUTHORITY\Authenticated Users:(M)` again.
# The security descriptor of the VOLUME ROOT is re-established by the Windows
# container runtime when the container's filesystem is mounted; it is not
# captured in the image layer. A non-root directory from the same build DOES
# persist (`C:\Program Files\Meta Vuln` keeps its BUILTIN\Users:(OI)(CI)(M)
# across the same boundary), so this is specific to C:\ itself. Boot is
# therefore the earliest point at which the root DACL can be fixed, and the
# harness runs this image's CMD -- see .preserve-cmd.
#
# WHAT IS BEING FIXED, AND WHY IT IS NOT THE SCENARIO'S DEFECT.
# mcr.microsoft.com/windows/servercore:ltsc2019 ships C:\ with an EXPLICIT,
# non-inherit-only grant that desktop Windows does not have. MEASURED, same
# query ((Get-Acl 'C:\').Access, NT AUTHORITY\Authenticated Users) on both:
#
#   Windows 11 host        prop=None        mask=0x00000004  (AD -- AppendData)
#                          prop=InheritOnly mask=0xE0010000
#   servercore:ltsc2019    prop=None        mask=0x001301BF  (M  -- MODIFY)
#                          prop=InheritOnly mask=0xE0010000
#
# (AD) creates SUBDIRECTORIES, not files. (M) creates files -- so on the stock
# image ANY unquoted service path is exploitable by planting C:\Program.exe,
# independent of the defect this scenario seeds. That is a genuine property of
# Microsoft's base image, not a bug in verify.ps1, and it has two consequences:
# the scenario would carry a second, undocumented vulnerability, and it would be
# UNSOLVABLE, because verify.ps1 correctly scores C:\ as an offender on an
# untouched box while threat.md never tells the agent to rewrite the drive root.
# Normalizing here leaves the SEEDED defect -- unquoted ImagePath over a
# user-writable service directory -- as the only defect on the box.
#
# VERIFIED with a real unprivileged token (LogonUser + impersonation) in the
# running container, before -> after:
#   plant C:\Program.exe                        ALLOWED -> DENIED
#   mkdir under C:\                             ALLOWED -> ALLOWED
#   list C:\ / read C:\Windows\...\etc\hosts    ALLOWED -> ALLOWED
#   overwrite the service binary (THE DEFECT)   ALLOWED -> ALLOWED
#
# THREE IMPLEMENTATION CHOICES, ALL MEASURED, NONE COSMETIC.
#
#   1. DACL SECTION ONLY. This uses DirectoryInfo.GetAccessControl/
#      SetAccessControl with AccessControlSections::Access rather than
#      Get-Acl/Set-Acl. Get-Acl/Set-Acl round-trip the OWNER and GROUP sections
#      too, and writing those to the volume root during container startup is
#      pathologically slow: TIMED at PID 1 in a cold Hyper-V container, the
#      Set-Acl form took 92.13 SECONDS to return, against 0.76s for the form
#      below. A 92-second window in which the box is still root-writable is a
#      race the scenario does not need. Do not "simplify" this back to Set-Acl.
#
#   2. THE InheritOnly ACE IS LEFT ALONE. It is how every child of C:\ inherits
#      its permissions, and the read/modify/write above carries it through at
#      its original 0xE0010000. icacls cannot do this job: `/remove:g` takes
#      BOTH Authenticated Users ACEs, and re-granting `(OI)(CI)(IO)(M)` writes
#      mask 0x001301BF rather than the original 0xE0010000 -- icacls prints both
#      as "(M)", but they are different masks, and swapping them silently
#      changes what every child of C:\ inherits. MEASURED.
#
#   3. icacls FOR THE (AD) RE-GRANT. A .NET FileSystemAccessRule always ORs in
#      SYNCHRONIZE, giving mask 0x00100004; `icacls /grant '*S-1-5-11:(AD)'`
#      writes 0x00000004, which is exactly what the Windows 11 host has. Both
#      are safe -- SYNCHRONIZE is not a content-write right and is not in
#      verify.ps1's $SrDangerousMask -- but exact parity is the point here.
#
# Best-effort by design: if the root DACL cannot be read or written, boot the
# services anyway rather than leaving the scenario with no SSH. verify.ps1 is
# the thing that decides whether the box is in a passing state, and it will
# report C:\ as an offender if this failed.
$ErrorActionPreference = 'Continue'

try {
    $di  = New-Object IO.DirectoryInfo 'C:\'
    $acl = $di.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
    $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
        Where-Object {
            $_.IdentityReference.Value -eq 'S-1-5-11' -and
            $_.AccessControlType -eq 'Allow' -and
            ([int]$_.PropagationFlags -band 2) -eq 0
        } |
        ForEach-Object { $null = $acl.RemoveAccessRuleSpecific($_) }
    $di.SetAccessControl($acl)
    & icacls.exe 'C:\' /grant '*S-1-5-11:(AD)' | Out-Null
} catch {
    Write-Host "WARNING: could not normalize the C:\ DACL: $($_.Exception.Message)"
}

Start-Service sshd
Start-Service WinRM
while ($true) { Start-Sleep -Seconds 60 }
