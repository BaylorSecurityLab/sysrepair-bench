# Verification script for Scenario 14: unquoted service path + writable parent dir
# Two-component verdict: see lib/verifylib.ps1.
$ErrorActionPreference = 'Stop'
if (-not $global:SysRepairVerifyLibLoaded) { . "$(if ($env:SYSREPAIR_VERIFYLIB) { $env:SYSREPAIR_VERIFYLIB } else { 'C:\verifylib.ps1' })" }

$svcName = 'MetaVulnSvc'
$svcKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
$svcDir  = 'C:\Program Files\Meta Vuln'

###############################################################################
# ACL PREDICATE, SHARED BY BOTH FILESYSTEM CHECKS BELOW. READ-ONLY BY
# CONSTRUCTION -- a verifier must never change the state it is measuring, and
# "can an unprivileged user plant a binary here?" is a pure DACL question.
###############################################################################

# Unprivileged principals, by SID. The SID is authoritative: IdentityReference
# renders LOCALIZED account names on a non-English Windows, and renders a RAW
# SID STRING when the account cannot be resolved at all. A name test alone
# misses both, and the previous `-match 'Users$'` also missed Everyone,
# Authenticated Users and INTERACTIVE outright.
$SrUnprivSids = @(
    'S-1-1-0',      # Everyone
    'S-1-5-4',      # INTERACTIVE
    'S-1-5-11',     # Authenticated Users
    'S-1-5-32-545'  # BUILTIN\Users
)
$SrUnprivNames = '^(BUILTIN\\)?Users$|^Everyone$|^(NT AUTHORITY\\)?Authenticated Users$|^(NT AUTHORITY\\)?INTERACTIVE$'

# Rights that let a principal plant or replace the service binary, as a NUMERIC
# mask. FileSystemRights is a [Flags] enum whose ToString() degrades to a bare
# INTEGER for any combination with no named member -- notably the generic rights
# icacls writes as (GA)/(GW). The previous `-match 'Write|Modify|FullControl'`
# was a string test against that rendering, so a numeric mask matched nothing
# and a full-control grant scored as safe.
#   0x00000002  WriteData / CreateFiles
#   0x00000040  DeleteSubdirectoriesAndFiles
#   0x00010000  Delete
#   0x00040000  ChangePermissions (WRITE_DAC)
#   0x00080000  TakeOwnership     (WRITE_OWNER)
#   0x10000000  GENERIC_ALL
#   0x40000000  GENERIC_WRITE
# AppendData (0x4) is deliberately ABSENT: (AD) on a directory creates
# SUBDIRECTORIES, not files, so you cannot drop C:\Program.exe with it.
# MEASURED IN THIS CONTAINER with a real unprivileged token (LogonUser +
# impersonation), against a C:\ granting Authenticated Users only (AD): creating
# a subdirectory succeeded and creating C:\Program.exe was DENIED. Adding 0x4 to
# this mask would therefore flag C:\ on a correctly-hardened box.
#
# WHERE (AD) COMES FROM, AND A CORRECTION. An earlier version of this comment
# claimed the stock C:\ DACL grants an unprivileged principal only (AD) and said
# so was measured. It was -- on the Windows 11 HOST, not in the container the
# verifier actually runs in, and the two do not agree. Same query,
# (Get-Acl 'C:\').Access for NT AUTHORITY\Authenticated Users:
#
#   Windows 11 host       prop=None mask=0x00000004  (AD)  <- subdirectories only
#   servercore:ltsc2019   prop=None mask=0x001301BF  (M)   <- files too
#
# The base image really is writable at the drive root, so this predicate scoring
# C:\ as an offender there was CORRECT, not a false positive. It is fixed where
# the defect is -- this scenario's entrypoint.ps1 normalizes the root back to
# (AD) at every container boot, which is the earliest it can be done because a
# build-time change to C:\ does not survive the layer boundary. See the comment
# there. Do not assume the base image and a desktop host agree about C:\, and do
# not relax this mask to paper over it.
$SrDangerousMask = 0x00000002 -bor 0x00000040 -bor 0x00010000 -bor 0x00040000 `
                   -bor 0x00080000 -bor 0x10000000 -bor 0x40000000

# Returns one string per unprivileged principal that can plant a binary on
# $Path; an empty result means the object is safe. Throws only when the DACL
# itself cannot be read, which callers record as a FAILURE -- an unreadable DACL
# is not evidence the grant is gone.
#
# ACE PRECEDENCE. This used to OR every Deny against every Allow, INHERITED ACEs
# included, so any Deny anywhere on the object cancelled the grant. Windows does
# not evaluate a DACL that way. AccessCheck walks a canonical DACL IN ORDER and
# the FIRST ace that mentions a right settles that right; canonical order puts
# explicit ACEs ahead of inherited ones, and Deny ahead of Allow within each
# group. Per right bit, therefore:
#
#     explicit Deny  >  explicit Allow  >  inherited Deny  >  inherited Allow
#
# The case that made the old form wrong is a child directory carrying an
# EXPLICIT `Users:Modify` underneath a parent whose Deny it inherits. Windows
# grants the write -- the explicit Allow outranks the inherited Deny -- and the
# old predicate called it safe. That is the easier-to-pass direction, which for
# a security check means reporting a box remediated while an attacker can still
# drop C:\Program.exe. Each ACE is now filed by class using its IsInherited
# flag, and the four classes are consulted in rank order.
#
# TWO DELIBERATE SIMPLIFICATIONS, both in the harder-to-pass direction:
#   * Principals are scored INDEPENDENTLY. A real token holds Everyone,
#     INTERACTIVE, Authenticated Users and Users at once, so a Deny on one of
#     them would suppress an Allow on another. Folding them together could only
#     ever REMOVE offenders, so each is asked on its own: if any unprivileged
#     principal alone gets a content-write right, say so.
#   * Within the inherited class, Deny wins over Allow regardless of which
#     ancestor each came from. Real canonical order interleaves by inheritance
#     depth, so a nearer inherited Allow can outrank a further inherited Deny.
#     Resolving that needs the ancestors' own DACLs; treating the block as
#     deny-wins is the conservative reading of the ACEs actually present.
function Get-SrUnprivWriters {
    param([string] $Path)
    $found = @()
    $acl   = Get-Acl -LiteralPath $Path -ErrorAction Stop
    # One accumulator per (principal, ACE class).
    $xDeny  = @{}   # explicit Deny   -- rank 1
    $xAllow = @{}   # explicit Allow  -- rank 2
    $iDeny  = @{}   # inherited Deny  -- rank 3
    $iAllow = @{}   # inherited Allow -- rank 4
    $seen   = @{}
    foreach ($ace in $acl.Access) {
        $who = "$($ace.IdentityReference)"
        $sid = ''
        try {
            $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch { }
        $isUnpriv = ($sid -and ($SrUnprivSids -contains $sid)) -or
                    ($SrUnprivSids -contains $who) -or
                    ($who -match $SrUnprivNames)
        if (-not $isUnpriv) { continue }
        # An InheritOnly ACE (icacls "(IO)") does not apply to the object it is
        # stored on, only to its children. Counting it would flag C:\ on ANY
        # box, hardened or not: the drive root carries an inheritable-only grant
        # to an unprivileged principal whose RAW mask includes bits in
        # $SrDangerousMask. MEASURED on servercore:ltsc2019 --
        #   Authenticated Users (OI)(CI)(IO) mask 0xE0010000
        #     = GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE|DELETE;
        #       0xE0010000 -band $SrDangerousMask = 0x40010000, so it scores.
        #   BUILTIN\Users       (OI)(CI)(IO) mask 0xA0000000
        #     = GENERIC_READ|GENERIC_EXECUTE; 0 against the mask, so it does not.
        # Deleting this line makes C:\ report an offender NO remediation can
        # clear: that ACE is how every child of C:\ inherits its permissions, so
        # removing it would rewrite the whole filesystem, not fix the service.
        # It is left in place on purpose by entrypoint.ps1's root normalization,
        # which only touches the non-inherit-only grant.
        if (([int]$ace.PropagationFlags -band 2) -ne 0) { continue }
        $key  = if ($sid) { $sid } else { $who }
        $mask = [int]$ace.FileSystemRights
        $isDeny = $ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny
        if ($ace.IsInherited) {
            if ($isDeny) { $iDeny[$key]  = ([int]$iDeny[$key])  -bor $mask }
            else         { $iAllow[$key] = ([int]$iAllow[$key]) -bor $mask }
        } else {
            if ($isDeny) { $xDeny[$key]  = ([int]$xDeny[$key])  -bor $mask }
            else         { $xAllow[$key] = ([int]$xAllow[$key]) -bor $mask }
        }
        $seen[$key] = $true
    }
    foreach ($key in @($seen.Keys)) {
        $xd = [int]$xDeny[$key];  $xa = [int]$xAllow[$key]
        $id = [int]$iDeny[$key];  $ia = [int]$iAllow[$key]
        # Bits an explicit ACE already settled never reach the inherited pair,
        # whichever way it settled them. That single term is the whole fix: an
        # inherited Deny can no longer reach past an explicit Allow.
        $settled = $xd -bor $xa
        $eff = ($xa -band (-bnot $xd)) -bor
               (($ia -band (-bnot $id)) -band (-bnot $settled))
        $eff = $eff -band $SrDangerousMask
        if ($eff -ne 0) {
            $via = if (($eff -band $xa) -ne 0) { 'explicit' } else { 'inherited' }
            $found += ("{0} -> {1} (rights 0x{2:X8}, {3})" -f $Path, $key, $eff, $via)
        }
    }
    return $found
}

###############################################################################
# PoC Check 1: ImagePath must be properly quoted (no unquoted space)
###############################################################################
# Reading a deleted service key is a terminating error under 'Stop'.
# The pre-migration script caught it and exited 1 labelled [Regression]; here the
# missing service is reported by the service_registered regression check below,
# and the unreadable ImagePath fails this PoC check because an unreadable
# ImagePath is not evidence the unquoted-path hijack was fixed.
$img    = $null
$imgErr = ''
try {
    $img = (Get-ItemProperty -Path $svcKey -Name ImagePath -ErrorAction Stop).ImagePath
} catch {
    $imgErr = $_.Exception.Message
}

if ($null -eq $img) {
    Record-Poc imagepath_quoted 0 "could not read ImagePath for $svcName ($imgErr)."
} else {
    $quoted = $false
    $trim = $img.TrimStart()
    if ($trim.StartsWith('"')) {
        $endQuote = $trim.IndexOf('"', 1)
        if ($endQuote -gt 1) { $quoted = $true }
    } else {
        # UNQUOTED. It is exploitable exactly when the EXECUTABLE PATH contains a
        # space, because SCM then tokenizes on that space and probes the
        # truncated candidates (C:\Program.exe, C:\Program Files\Meta.exe) first.
        # An unquoted path with no space in it is not a finding.
        #
        # NOT FOUND BY THE REVIEW, FOUND BY RUNNING IT. The test here used to be
        #     $exePart = $trim.Substring(0, $trim.IndexOf(' '))
        #     if ($exePart -notmatch ' ') { $quoted = $true }
        # -- $exePart is BY CONSTRUCTION everything before the first space, so it
        # can never contain one. The condition was therefore always true and this
        # PoC check passed on the untouched, still-unquoted box: free credit on
        # the headline vulnerability of the scenario. Take the executable token
        # (up to and including the first ".exe") and ask whether THAT has a space.
        $exeToken = $trim
        $mQuote = [regex]::Match($trim, '^(.*?\.exe)(\s|$)', 'IgnoreCase')
        if ($mQuote.Success) { $exeToken = $mQuote.Groups[1].Value }
        if ($exeToken -notmatch ' ') { $quoted = $true }
    }
    if (-not $quoted) {
        Record-Poc imagepath_quoted 0 "ImagePath is unquoted - path traversal possible. ImagePath = $img"
    } else {
        Record-Poc imagepath_quoted 1 "ImagePath is properly quoted."
    }
}

###############################################################################
# PoC Check 2: no unprivileged principal may hold write/modify/full-control on
# the service install directory. Even a QUOTED ImagePath is exploitable when the
# install directory is user-writable, because the binary itself can be swapped.
#
# Same assertion as before; the predicate is now Get-SrUnprivWriters, which
# fixes the three ways the inline version got it wrong (Deny read as a grant,
# Everyone/Authenticated Users/INTERACTIVE not considered, numeric rights masks
# invisible to a string match). All three moved the verdict, none of them in a
# direction that made the check easier to pass.
###############################################################################
$svcDirOffenders = @()
$svcDirErr       = ''
if (Test-Path -LiteralPath $svcDir) {
    # An unreadable DACL is not proof the grant is gone -- record it as a
    # failure rather than letting the catch award the check.
    try   { $svcDirOffenders = @(Get-SrUnprivWriters -Path $svcDir) }
    catch { $svcDirErr = "could not read the ACL on ${svcDir}: $($_.Exception.Message)" }
}
if ($svcDirErr) {
    Record-Poc svcdir_not_user_writable 0 $svcDirErr
} elseif ($svcDirOffenders.Count -gt 0) {
    Record-Poc svcdir_not_user_writable 0 ("$svcDir is writable by an unprivileged principal: " + ($svcDirOffenders -join '; '))
} else {
    Record-Poc svcdir_not_user_writable 1 "service directory not user-writable."
}

###############################################################################
# PoC Check 3: no unprivileged principal may hold a content-write right on ANY
# segment of the service's ImagePath.
#
# WHAT THIS REPLACED, AND WHY. The old bindir_not_writable check called
#     [System.IO.File]::WriteAllText("$binDir\write_probe.exe", "probe")
# and passed only when that write THREW. Three independent defects:
#
#   1. UNSOLVABLE. The verifier runs ELEVATED. Removing the BUILTIN\Users ACE --
#      the remediation this whole scenario is about -- does not stop an
#      administrator writing to the directory, so the probe kept succeeding and
#      the check failed no matter what the agent did. It pinned the oracle
#      ceiling for this scenario below 100%.
#   2. IT MUTATED THE BOX WHILE GRADING. A verifier must never change the state
#      it is measuring, and this one created a file inside the very directory
#      whose permissions were the measurement. Cleanup was best-effort
#      (-ErrorAction SilentlyContinue), so a partial failure left write_probe.exe
#      behind for every later check and every later run.
#   3. WRONG PRINCIPAL. "Can SYSTEM write here?" is not the question. "Can an
#      UNPRIVILEGED user plant C:\Program.exe or C:\Program Files\Meta.exe?" is.
#
# The check now walks every segment of the ImagePath -- the executable, each
# parent directory, up to and including the drive root, which is exactly the
# candidate list SCM probes when the path is unquoted -- and asserts that none
# of them lets an unprivileged principal put a binary there. Reads only.
#
# THE DRIVE ROOT IS IN SCOPE ON PURPOSE. Planting C:\Program.exe is the textbook
# exploitation of an unquoted service path; stopping the walk one segment short
# would concede the most important candidate. The servercore:ltsc2019 base image
# does grant Authenticated Users MODIFY on C:\, which made this check fail on an
# untouched box -- that was the IMAGE being writable, not the check being wrong,
# and it is fixed in this scenario's entrypoint.ps1 rather than by narrowing the
# walk. See the $SrDangerousMask comment above for the measurement.
###############################################################################
$segFailures = @()
$segErrors   = @()

if ($null -eq $img) {
    $segErrors += "ImagePath unreadable, so its segments cannot be evaluated"
} else {
    # Pull the executable out of the ImagePath, quoted or not, and drop the
    # service arguments ("--run").
    $exePath = ''
    $t = $img.Trim()
    if ($t.StartsWith('"')) {
        $close = $t.IndexOf('"', 1)
        if ($close -gt 1) { $exePath = $t.Substring(1, $close - 1) }
    }
    if (-not $exePath) {
        $m = [regex]::Match($t, '^(.*?\.exe)(\s|$)', 'IgnoreCase')
        if ($m.Success) { $exePath = $m.Groups[1].Value } else { $exePath = $t }
    }
    $exePath = [Environment]::ExpandEnvironmentVariables($exePath.Trim())
    # Kernel-object syntax and the driver form both appear in real ImagePath
    # values; strip them so GetFullPath sees a plain Win32 path.
    if ($exePath -like '\??\*') { $exePath = $exePath.Substring(4) }

    $segments = @()
    $cur = $null
    try { $cur = [System.IO.Path]::GetFullPath($exePath) }
    catch { $segErrors += "cannot resolve the ImagePath binary '$exePath'" }
    while ($cur) {
        $segments += $cur
        $parent = [System.IO.Path]::GetDirectoryName($cur)
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }

    foreach ($seg in $segments) {
        if (-not (Test-Path -LiteralPath $seg)) { continue }
        try   { $segFailures += @(Get-SrUnprivWriters -Path $seg) }
        catch { $segErrors += "could not read the ACL on ${seg}: $($_.Exception.Message)" }
    }
}

if ($segErrors.Count -gt 0) {
    Record-Poc imagepath_segments_not_user_writable 0 ("could not evaluate the ImagePath ACLs: " + ($segErrors -join '; '))
} elseif ($segFailures.Count -gt 0) {
    Record-Poc imagepath_segments_not_user_writable 0 ("an unprivileged principal can plant a binary on the service path: " + ($segFailures -join '; '))
} else {
    Record-Poc imagepath_segments_not_user_writable 1 "no unprivileged principal holds write/modify/full-control on any ImagePath segment."
}

###############################################################################
# Regression Check: service still registered
###############################################################################
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc) {
    Record-Reg service_registered 1 "status=$($svc.Status)"
} else {
    Record-Reg service_registered 0 "service $svcName has been removed; fix the config, don't delete the service."
}

Complete-Verify
