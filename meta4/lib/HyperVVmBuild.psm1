#Requires -RunAsAdministrator
<#
.SYNOPSIS
Profile-driven build engine shared by the Hyper-V kernel VMs.

.DESCRIPTION
The companion to HyperVVmOps.psm1: that module runs an already-built VM, this one
bakes it. meta4/kernel-vm and meta4/dirtypipe-vm differ only in Ubuntu suite,
pinned kernel, addresses, MACs, key and port -- the image conversion, cloud-init
seed ISO, VM creation, provisioning wait and ABI gate were duplicated verbatim.

Each VM's *Lab.ps1 keeps its public entry point (Install-KernelLab,
Install-DirtyPipeLab) and supplies a profile:

    @{ Tag='kernel'; VmName='meta4-kernel'; Suite='jammy'; KernelSeries='5.15.0'
       Abi=25; GuestIp='10.20.40.5'; SshPort=2224; ... }

NO FUNCTION HERE MAY BE NAMED AFTER A HYPER-V CMDLET. PowerShell resolves command
names case-insensitively, so a function called New-Vm or Start-Vm shadows New-VM /
Start-VM everywhere inside the module -- including in its own body, where the call
then binds against the function's own parameters and dies on an unknown -Name.
Hence New-LabVm, Remove-LabVm, and so on; Assert-LabCmdletNames below is the
regression test for it.

Two cloud-init traps are handled once here so neither VM can regress on them:

  * user-data MUST begin with the bytes '#cloud-config'. WriteAllText's default
    encoding in PowerShell 5.1 emits a UTF-8 BOM, which pushes the marker off the
    front; cloud-init then treats the payload as unknown and the guest boots
    unconfigured. The BOM is invisible in every text editor.
  * netplan matches `macaddress` case-sensitively. An uppercase literal matches
    nothing, both interfaces stay unconfigured, and the guest boots with no
    network at all -- indistinguishable from a hung VM from the host side.
#>

Set-StrictMode -Version Latest

# Every key the engine reads. Validated up front because Set-StrictMode -Version
# Latest turns a missing hashtable key into a PropertyNotFoundException thrown
# from deep inside whichever function happened to touch it first, which says
# nothing useful about the profile that is actually incomplete.
$script:RequiredKeys = @(
    'Tag', 'VmName', 'Suite', 'KernelSeries', 'Abi', 'AbiRationale',
    'CloudImage', 'CloudImageSha', 'BuildSwitch', 'LabSwitch',
    'GuestUser', 'GuestIp', 'GuestCidr', 'KeyPath', 'KeyComment',
    'NatMac', 'LabMac', 'VhdRoot', 'ScenarioDir'
)


function Assert-LabProfile {
    param([Parameter(Mandatory)][hashtable] $Lab)
    $missing = $script:RequiredKeys | Where-Object { -not $Lab.ContainsKey($_) }
    if ($missing) {
        throw "Assert-LabProfile: profile is missing required key(s): $($missing -join ', ')"
    }
}


function Get-LabKernelVersion {
    param([Parameter(Mandatory)][hashtable] $Lab)
    "$($Lab.KernelSeries)-$($Lab.Abi)-generic"
}


function Get-LabUnitPrefix {
    <#
    .DESCRIPTION
    Names the stage-2 systemd unit, its log, and its completion marker. Derived
    from Tag so the two VMs cannot collide if they are ever baked side by side.
    #>
    param([Parameter(Mandatory)][hashtable] $Lab)
    "srb-$($Lab.Tag)"
}


function New-LabSshKey {
    param([Parameter(Mandatory)][hashtable] $Lab)

    $path = $Lab.KeyPath
    if (Test-Path $path) { Write-Host "[$($Lab.Tag)] reusing key $path"; return "$path.pub" }
    $dir = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ssh-keygen -t ed25519 -f $path -N '""' -C $Lab.KeyComment | Out-Null
    if (-not (Test-Path "$path.pub")) {
        throw 'New-LabSshKey: ssh-keygen produced no public key. Is the OpenSSH client installed?'
    }
    Write-Host "[$($Lab.Tag)] generated $path"
    return "$path.pub"
}


function Test-LabCloudImage {
    <#
    .SYNOPSIS
    Fail loudly if the base image is missing or altered.
    #>
    param([Parameter(Mandatory)][hashtable] $Lab)

    if (-not (Test-Path $Lab.CloudImage)) {
        # Suite appears in both the path and the filename upstream; deriving both
        # from one field is what stops a copied script advertising a URL like
        # .../jammy/current/focal-server-cloudimg-amd64.img, which 404s.
        $url = "https://cloud-images.ubuntu.com/$($Lab.Suite)/current/$($Lab.Suite)-server-cloudimg-amd64.img"
        throw @"
Cloud image not found: $($Lab.CloudImage)
Download it with:
  curl -o "$($Lab.CloudImage)" $url
"@
    }
    Write-Host "[$($Lab.Tag)] verifying image checksum..."
    $got = (Get-FileHash $Lab.CloudImage -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $Lab.CloudImageSha) {
        throw "Cloud image checksum mismatch.`n  expected $($Lab.CloudImageSha)`n  got      $got"
    }
    Write-Host "[$($Lab.Tag)] checksum OK"
}


function Convert-LabImageToVhdx {
    <#
    .SYNOPSIS
    qcow2 -> VHDX. Canonical ships no VHDX for these suites, so conversion is
    unavoidable.
    #>
    param([Parameter(Mandatory)][hashtable] $Lab,
          [Parameter(Mandatory)][string] $VhdxPath)

    $qemu = (Get-Command qemu-img -ErrorAction SilentlyContinue).Source
    if (-not $qemu) { $qemu = Join-Path $HOME 'scoop\apps\qemu\current\qemu-img.exe' }
    if (-not (Test-Path $qemu)) {
        throw 'Convert-LabImageToVhdx: qemu-img not found. Install with: scoop install qemu'
    }

    $sparse = [IO.Path]::ChangeExtension($VhdxPath, '.sparse.vhdx')
    foreach ($p in @($sparse, $VhdxPath)) { if (Test-Path $p) { Remove-Item $p -Force } }

    Write-Host "[$($Lab.Tag)] converting cloud image to VHDX (this takes a minute)..."
    & $qemu convert -f qcow2 -O vhdx -o subformat=dynamic $Lab.CloudImage $sparse
    if ($LASTEXITCODE -ne 0) { throw "qemu-img convert failed ($LASTEXITCODE)" }

    Write-Host "[$($Lab.Tag)] rewriting densely (Hyper-V rejects sparse VHDX)"
    fsutil sparse setflag $sparse 0 2>&1 | Out-Null
    Copy-Item $sparse $VhdxPath -Force
    Remove-Item $sparse -Force

    # Cloud images ship a small root; the kernel + Docker + scenario images need room.
    Resize-VHD -Path $VhdxPath -SizeBytes 40GB
    Write-Host "[$($Lab.Tag)] VHDX ready: $VhdxPath"
}


function New-LabSeedIso {
    <#
    .SYNOPSIS
    Builds the cloud-init NoCloud (CIDATA) seed ISO.

    .DESCRIPTION
    Hyper-V has no cloud-init datasource, so an attached ISO labelled CIDATA is
    the mechanism. Needs oscdimg from the Windows ADK Deployment Tools.

    The two provisioning stages are the EXISTING per-VM repo scripts, embedded
    verbatim rather than reimplemented -- they encode the kernel-pinning logic and
    the ABI safety gate, and duplicating that would let the two drift.

    Stage 2 cannot be a plain runcmd: it must execute AFTER the reboot into the
    pinned kernel. It is installed as a systemd oneshot that disables itself.
    #>
    param([Parameter(Mandatory)][hashtable] $Lab,
          [Parameter(Mandatory)][string] $IsoPath,
          [Parameter(Mandatory)][string] $PublicKey)

    Assert-LabProfile -Lab $Lab
    $unit = Get-LabUnitPrefix -Lab $Lab
    $kernelVersion = Get-LabKernelVersion -Lab $Lab

    # Read from disk, never inlined here. This is a DOUBLE-QUOTED here-string, so
    # PowerShell would interpolate any $(...) or ${...} a shell script contains --
    # an inlined script with $(dpkg-query ...) and || is a parse error, not a
    # runtime surprise. Reading the file and splicing the finished string keeps
    # shell syntax out of PowerShell's parser entirely.
    $stage1  = Get-Content (Join-Path $Lab.ScenarioDir 'install-old-kernel.sh') -Raw
    $stage1b = Get-Content (Join-Path $Lab.ScenarioDir 'harden-boot.sh') -Raw
    $stage2  = Get-Content (Join-Path $Lab.ScenarioDir 'provision.sh') -Raw
    $indent = { param($t) ($t -split "`r?`n" | ForEach-Object { "      $_" }) -join "`n" }

    $userData = @"
#cloud-config
hostname: $($Lab.VmName)
users:
  - name: $($Lab.GuestUser)
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $PublicKey
ssh_pwauth: false
package_update: true
packages:
  # Provides hv_kvp_daemon. Without it Hyper-V's Key-Value Pair service reports
  # "No Contact" and Get-VMNetworkAdapter returns no IPAddresses. Nothing here
  # depends on that (eth1 has a fixed address) but it makes the VM introspectable.
  - linux-cloud-tools-virtual

write_files:
  - path: /usr/local/sbin/stage1-install-old-kernel.sh
    permissions: '0755'
    content: |
$(& $indent $stage1)
  - path: /usr/local/sbin/stage2-provision.sh
    permissions: '0755'
    content: |
$(& $indent $stage2)
  - path: /usr/local/sbin/stage1b-harden-boot.sh
    permissions: '0755'
    content: |
$(& $indent $stage1b)

  - path: /etc/systemd/system/$unit-stage2.service
    permissions: '0644'
    content: |
      [Unit]
      Description=SysRepair-Bench kernel VM stage 2 (post-reboot)
      After=network-online.target
      Wants=network-online.target
      [Service]
      Type=oneshot
      RemainAfterExit=yes
      ExecStart=/usr/local/sbin/stage2-provision.sh
      ExecStartPost=/bin/sh -c 'systemctl disable $unit-stage2.service; touch /var/lib/$unit-ready'
      StandardOutput=append:/var/log/$unit-stage2.log
      StandardError=append:/var/log/$unit-stage2.log
      [Install]
      WantedBy=multi-user.target

runcmd:
  - [ systemctl, enable, $unit-stage2.service ]
  - [ /bin/bash, /usr/local/sbin/stage1-install-old-kernel.sh ]
  - [ /bin/bash, /usr/local/sbin/stage1b-harden-boot.sh ]

power_state:
  mode: reboot
  message: rebooting into $kernelVersion
  timeout: 60
  condition: true
"@

    $metaData = @"
instance-id: $($Lab.VmName)-001
local-hostname: $($Lab.VmName)
"@

    # Matched BY MAC: with two NICs, kernel naming (eth0/eth1 vs ens*/enp*) is
    # not guaranteed stable and a name glob would apply one config to both.
    #
    # nat: DHCP + default route, for apt during the bake.
    # lab: fixed address on the Internal switch, the only thing host-side code
    #      relies on. `optional: true` stops systemd-networkd-wait-online
    #      blocking boot for ~2 min once the NAT NIC is later disconnected.
    #
    # This must be network-config, not a netplan file dropped via write_files +
    # `netplan apply` in runcmd: that rewrites config after the interface is
    # already up, and the lab address never comes up
    # (see meta4/ad-vm/lab/New-AttackerVM.ps1:137-145).
    # LOWERCASE MACs -- see the module header; an uppercase literal matches no
    # interface and the guest boots with no network at all. Cost one build.
    #
    # No set-name: renaming buys nothing here and is another way for the match
    # to fail. Names are irrelevant since nothing addresses them by name.
    $networkConfig = @"
version: 2
ethernets:
  nat:
    match:
      macaddress: "$($Lab.NatMac.ToLower())"
    dhcp4: true
    optional: true
  lab:
    match:
      macaddress: "$($Lab.LabMac.ToLower())"
    dhcp4: false
    optional: true
    addresses:
      - $($Lab.GuestCidr)
"@

    $staging = Join-Path $env:TEMP "$unit-cidata"
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging -Force | Out-Null

    # LF endings: cloud-init parses these as YAML and CRLF breaks block scalars.
    # UTF8Encoding($false) — see the module header on the BOM.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    foreach ($f in @(@{n='user-data';c=$userData}, @{n='meta-data';c=$metaData},
                     @{n='network-config';c=$networkConfig})) {
        [IO.File]::WriteAllText((Join-Path $staging $f.n), ($f.c -replace "`r`n", "`n"), $utf8NoBom)
    }

    # Fail loudly if the marker is not the very first bytes — this is what a BOM
    # breaks, and it is the failure mode that costs an hour to diagnose.
    $head = -join ([IO.File]::ReadAllBytes((Join-Path $staging 'user-data'))[0..12] |
                   ForEach-Object { [char]$_ })
    if ($head -ne '#cloud-config') {
        throw "New-LabSeedIso: user-data must begin with '#cloud-config'; got '$head'"
    }

    $oscdimg = (Get-Command oscdimg.exe -ErrorAction SilentlyContinue).Source
    if (-not $oscdimg) {
        $oscdimg = Get-ChildItem 'C:\Program Files (x86)\Windows Kits' -Recurse -Filter 'oscdimg.exe' `
                     -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $oscdimg) {
        throw 'New-LabSeedIso: oscdimg.exe not found. Install the Windows ADK "Deployment Tools" feature.'
    }

    if (Test-Path $IsoPath) { Remove-Item $IsoPath -Force }
    # -j1 keeps Joliet names case-correct; cloud-init looks for lowercase
    # "user-data" and silently ignores the seed if it arrives as "USER-DAT".
    & $oscdimg -j1 -lCIDATA -m -o $staging $IsoPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "oscdimg failed ($LASTEXITCODE)" }
    Write-Host "[$($Lab.Tag)] seed ISO: $IsoPath"
}


function Remove-LabVm {
    <#
    .SYNOPSIS
    Tear down any existing VM. MUST run before the VHDX is rewritten.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Lab)

    if (-not (Get-VM -Name $Lab.VmName -ErrorAction SilentlyContinue)) { return }
    Write-Host "[$($Lab.Tag)] removing existing $($Lab.VmName)"
    Stop-VM -Name $Lab.VmName -TurnOff -Force -ErrorAction SilentlyContinue
    # Checkpoints keep their own differencing disks open; drop them first or the
    # VHDX stays locked after the VM is gone.
    Get-VMSnapshot -VMName $Lab.VmName -ErrorAction SilentlyContinue |
        Remove-VMSnapshot -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Remove-VM -Name $Lab.VmName -Force
    Start-Sleep -Seconds 2
}


function New-LabVm {
    param([Parameter(Mandatory)][hashtable] $Lab,
          [Parameter(Mandatory)][string] $VhdxPath)

    Remove-LabVm -Lab $Lab

    # Gen 2 = UEFI.
    New-VM -Name $Lab.VmName -Generation 2 `
           -MemoryStartupBytes (4GB) -VHDPath $VhdxPath -SwitchName $Lab.BuildSwitch | Out-Null
    Set-VM -Name $Lab.VmName -ProcessorCount 2 -AutomaticCheckpointsEnabled $false

    # SECURE BOOT MUST BE OFF, and not as a workaround.
    #
    # Ubuntu's shim revokes superseded signed kernels (SBAT generation numbers,
    # and DBX for the worst cases) precisely to stop an attacker downgrading a
    # patched machine to a vulnerable kernel. The kernel this VM pins is exactly
    # such a revoked build -- which is Secure Boot working as designed. Booting a
    # deliberately vulnerable kernel is this VM's whole purpose, so the two goals
    # are fundamentally incompatible.
    #
    # Safe here: the VM has no route out after the bake and exists only to host
    # LPE scenario containers.
    Set-VMFirmware -VMName $Lab.VmName -EnableSecureBoot Off

    # NIC 1 (created with the VM) = NAT; NIC 2 = the isolated lab segment.
    Get-VMNetworkAdapter -VMName $Lab.VmName |
        Set-VMNetworkAdapter -StaticMacAddress ($Lab.NatMac -replace ':', '')
    Add-VMNetworkAdapter -VMName $Lab.VmName -SwitchName $Lab.LabSwitch `
                         -StaticMacAddress ($Lab.LabMac -replace ':', '')

    Write-Host "[$($Lab.Tag)] created $($Lab.VmName): nat=$($Lab.BuildSwitch) lab=$($Lab.LabSwitch)"
}


function Invoke-LabSsh {
    <#
    .SYNOPSIS
    Run a command in the guest. Never throws; returns exit code + output.
    #>
    param([Parameter(Mandatory)][hashtable] $Lab,
          [Parameter(Mandatory)][string] $Command,
          [int] $ConnectTimeout = 6)

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # LogLevel=ERROR: without it ssh prints "Warning: Permanently added ...
        # to the list of known hosts" on first contact, and because stderr is
        # merged into $out that warning becomes the FIRST line of the result --
        # which broke the ABI version match even though the guest had booted the
        # right kernel.
        $out = & ssh -i $Lab.KeyPath -o StrictHostKeyChecking=no `
                     -o UserKnownHostsFile=/dev/null -o BatchMode=yes `
                     -o LogLevel=ERROR -o ConnectTimeout=$ConnectTimeout `
                     "$($Lab.GuestUser)@$($Lab.GuestIp)" $Command 2>&1
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output   = (($out | ForEach-Object { "$_" }) -join "`n").Trim()
        }
    } finally { $ErrorActionPreference = $prev }
}


function Wait-LabProvisioned {
    <#
    .SYNOPSIS
    Block until stage 2 has run. A reboot happens mid-flight, so poll the marker
    rather than watching a single SSH session.
    #>
    param([Parameter(Mandatory)][hashtable] $Lab,
          [int] $TimeoutMinutes = 40)

    $unit = Get-LabUnitPrefix -Lab $Lab
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    Write-Host "[$($Lab.Tag)] waiting for provisioning (up to $TimeoutMinutes min; two boots)..."
    $lastNote = Get-Date
    while ((Get-Date) -lt $deadline) {
        $r = Invoke-LabSsh -Lab $Lab -Command "test -f /var/lib/$unit-ready && uname -r"
        if ($r.ExitCode -eq 0 -and $r.Output) {
            Write-Host "[$($Lab.Tag)] provisioned; running kernel $($r.Output)"
            return $r.Output
        }
        if (((Get-Date) - $lastNote).TotalMinutes -ge 2) {
            $reach = (Invoke-LabSsh -Lab $Lab -Command 'true').ExitCode -eq 0
            Write-Host ("[$($Lab.Tag)] still provisioning... ssh={0}" -f $(if ($reach) { 'up, stage2 pending' } else { 'not up yet' }))
            $lastNote = Get-Date
        }
        Start-Sleep -Seconds 20
    }
    throw "Wait-LabProvisioned: timed out after $TimeoutMinutes min. Check /var/log/$unit-stage2.log and /var/log/cloud-init-output.log in the guest."
}


function Assert-LabAbi {
    <#
    .SYNOPSIS
    The gate that makes this VM worth building. Wrong ABI => scenarios silently
    stop being exploitable, and verify.sh would "pass" for the wrong reason.
    #>
    param([Parameter(Mandatory)][hashtable] $Lab,
          [Parameter(Mandatory)][string] $Running)

    # Unanchored: a stray leading line must not break the match. Escaped because
    # the dots in a version are not wildcards.
    $pattern = [regex]::Escape($Lab.KernelSeries) + '-(\d+)-generic'
    if ($Running -notmatch $pattern) {
        throw "Assert-LabAbi: unexpected kernel '$Running'; wanted $(Get-LabKernelVersion -Lab $Lab)"
    }
    $abi = [int]$Matches[1]
    if ($abi -ne $Lab.Abi) {
        throw "Assert-LabAbi: booted ABI $abi, wanted $($Lab.Abi). GRUB pin did not take."
    }
    Write-Host "[$($Lab.Tag)] ABI $abi confirmed ($($Lab.AbiRationale))"
}


function Install-VmLab {
    <#
    .SYNOPSIS
    Full build: verify image -> convert -> seed -> create -> provision -> move
    to the lab segment -> checkpoint.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Lab)

    Assert-LabProfile -Lab $Lab

    # First, before anything touches the VHDX: a running VM holds it open.
    Remove-LabVm -Lab $Lab

    Test-LabCloudImage -Lab $Lab
    $pub  = (Get-Content (New-LabSshKey -Lab $Lab) -Raw).Trim()
    $vhdx = Join-Path $Lab.VhdRoot "$($Lab.VmName).vhdx"
    $iso  = Join-Path $Lab.VhdRoot "$($Lab.VmName)-cidata.iso"

    Convert-LabImageToVhdx -Lab $Lab -VhdxPath $vhdx
    New-LabSeedIso -Lab $Lab -IsoPath $iso -PublicKey $pub
    New-LabVm -Lab $Lab -VhdxPath $vhdx

    Add-VMDvdDrive -VMName $Lab.VmName -Path $iso
    Set-VMFirmware -VMName $Lab.VmName `
                   -FirstBootDevice (Get-VMHardDiskDrive -VMName $Lab.VmName)

    Start-VM -Name $Lab.VmName
    $running = Wait-LabProvisioned -Lab $Lab
    Assert-LabAbi -Lab $Lab -Running $running

    # Seed ISO carries the authorized key; detaching it after the bake keeps the
    # cloud-init datasource from re-running on later boots.
    Get-VMDvdDrive -VMName $Lab.VmName | Remove-VMDvdDrive

    # Cut the route out. The scenarios run privileged containers; they have no
    # business reaching the internet once provisioning is done. The lab NIC
    # (fixed address) is untouched, so host-side access is unaffected.
    Write-Host "[$($Lab.Tag)] disconnecting the NAT NIC; lab segment only from here"
    Get-VMNetworkAdapter -VMName $Lab.VmName |
        Where-Object { $_.MacAddress -eq ($Lab.NatMac -replace ':', '') } |
        Disconnect-VMNetworkAdapter

    Checkpoint-VM -Name $Lab.VmName -SnapshotName 'baseline'
    Write-Host "[$($Lab.Tag)] baseline checkpoint taken"
    Write-Host "[$($Lab.Tag)] DONE. kernel=$running"
}


function Assert-LabCmdletNames {
    <#
    .SYNOPSIS
    Regression test for the shadowing trap in this module's header: assert that
    every Hyper-V cmdlet the engine calls still resolves to the Hyper-V provider
    and not to one of our own functions.

    .DESCRIPTION
    Run inside the module's own scope, which is where the shadowing would bite:

        & (Get-Module HyperVVmBuild) { Assert-LabCmdletNames }
    #>
    $used = @('Get-VM', 'New-VM', 'Set-VM', 'Start-VM', 'Stop-VM', 'Remove-VM',
              'Get-VMSnapshot', 'Remove-VMSnapshot', 'Checkpoint-VM',
              'Get-VMNetworkAdapter', 'Set-VMNetworkAdapter',
              'Add-VMNetworkAdapter', 'Disconnect-VMNetworkAdapter',
              'Set-VMFirmware', 'Add-VMDvdDrive', 'Get-VMDvdDrive',
              'Remove-VMDvdDrive', 'Get-VMHardDiskDrive', 'Resize-VHD')
    $shadowed = foreach ($c in $used) {
        $r = Get-Command $c -ErrorAction SilentlyContinue
        if (-not $r) { "$c (NOT FOUND)" }
        elseif ($r.CommandType -eq 'Function') { "$c (shadowed by $($r.Source))" }
    }
    if ($shadowed) { throw "Assert-LabCmdletNames: $($shadowed -join '; ')" }
    Write-Host "[lib] $($used.Count) Hyper-V cmdlets resolve correctly; no shadowing"
}


Export-ModuleMember -Function Assert-LabProfile, Get-LabKernelVersion,
    Get-LabUnitPrefix, New-LabSshKey, Test-LabCloudImage, Convert-LabImageToVhdx,
    New-LabSeedIso, Remove-LabVm, New-LabVm, Invoke-LabSsh, Wait-LabProvisioned,
    Assert-LabAbi, Install-VmLab, Assert-LabCmdletNames
