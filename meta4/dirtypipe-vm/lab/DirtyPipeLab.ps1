#Requires -RunAsAdministrator
<#
.SYNOPSIS
Builds meta4-dirtypipe: Ubuntu 20.04 on Hyper-V pinned to HWE kernel 5.13.0-27,
with Docker, replacing the Vagrant/VirtualBox definition.

.DESCRIPTION
Deliberately NOT built by AutomatedLab -- its Linux support is materially thinner
than its Windows support, and this VM is a plain Docker host, not a domain. Same
reasoning as meta4/ad-vm/lab/New-AttackerVM.ps1, whose cloud-init/qemu-img
patterns this script reuses.

THE KERNEL IS THE POINT. meta4 scenarios S21 (GameOverlay, CVE-2023-2640/32629)
and S22 (nf_tables UAF, CVE-2024-1086) run as containers INSIDE this VM so they
share its kernel. Dirty Pipe (CVE-2022-0847) affects 5.8 <= k < 5.13.0-28, so
GameOverlay fix (ABI 75) and the nf_tables fix (ABI 97). If the VM boots anything
>= 75 the scenarios silently stop being exploitable and verify.sh "passes" for
the wrong reason -- so provision.sh hard-fails rather than continue.

NETWORKING. Two NICs, on purpose:

  eth0 -> 'Default Switch'  Hyper-V's NAT switch. DHCP + a route out for apt and
                            Docker's repo during the bake.
  eth1 -> SRB-Kernel        Internal, static 10.20.40.6. Always reachable from
                            the host, so nothing depends on guest tooling.

The first draft baked on SRB-Build (External) and moved the NIC afterwards,
copying New-AttackerVM. That does not work on this host: SRB-Build is bridged to
a *Wi-Fi* adapter, and Hyper-V External switches over wireless do not get the AP
to accept the guest's MAC, so the guest never gets DHCP and apt hangs with no
diagnostic. The NAT switch has no such problem.

Nor can host-side IP discovery use Get-VMNetworkAdapter's IPAddresses: that is
reported by the Key-Value Pair integration service, whose daemon
(linux-cloud-tools-virtual) is absent from stock Ubuntu cloud images -- KVP shows
"No Contact" and the list is empty. Hence the fixed address on eth1. The KVP
package is installed anyway so the field works for anyone looking later.

cloud-init matches the two NICs BY MAC, not by name: with two adapters, kernel
naming (eth0/eth1 vs ens*/enp*) is not guaranteed stable, and a name glob would
apply one config to both.

.EXAMPLE
    . .\DirtyPipeLab.ps1
    Install-DirtyPipeLab
#>

$ErrorActionPreference = 'Stop'

$script:DirtyPipeVmName    = 'meta4-dirtypipe'
$script:DirtyPipeAbi       = 27
$script:DirtyPipeVersion   = "5.13.0-$($script:DirtyPipeAbi)-generic"
$script:CloudImage      = 'C:\LabSources\ISOs\focal-server-cloudimg-amd64.img'
$script:CloudImageSha   = '18f2977d77dfea1b74aee14533bd21c34f789139e949c57023b7364894b7e5e9'
$script:BuildSwitch     = 'Default Switch'   # NAT; External-over-WiFi does not work
$script:LabSwitch       = 'SRB-Kernel'
$script:GuestUser       = 'vagrant'   # kept: run.py's docker-context contract
$script:GuestIp         = '10.20.40.6'
$script:GuestCidr       = '10.20.40.6/24'
$script:GuestGateway    = '10.20.40.1'
$script:SshPort         = 2225        # host-side; 2223 is HS13
$script:KeyPath         = Join-Path $HOME '.ssh\srb_dirtypipe'
$script:VhdRoot         = 'C:\ProgramData\Microsoft\Windows\Virtual Hard Disks'
$script:LabDir          = Split-Path -Parent $PSCommandPath
$script:ScenarioDir     = Split-Path -Parent $script:LabDir


function New-DirtyPipeSshKey {
    param([string] $Path = $script:KeyPath)
    if (Test-Path $Path) { Write-Host "[dirtypipe] reusing key $Path"; return "$Path.pub" }
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ssh-keygen -t ed25519 -f $Path -N '""' -C 'srb-dirtypipe' | Out-Null
    if (-not (Test-Path "$Path.pub")) {
        throw 'New-DirtyPipeSshKey: ssh-keygen produced no public key. Is the OpenSSH client installed?'
    }
    Write-Host "[dirtypipe] generated $Path"
    return "$Path.pub"
}


function Test-DirtyPipeCloudImage {
    <#
    .SYNOPSIS
    Fail loudly if the base image is missing or altered.
    #>
    if (-not (Test-Path $script:CloudImage)) {
        throw @"
Cloud image not found: $($script:CloudImage)
Download it with:
  curl -o "$($script:CloudImage)" https://cloud-images.ubuntu.com/jammy/current/focal-server-cloudimg-amd64.img
"@
    }
    Write-Host '[dirtypipe] verifying image checksum...'
    $got = (Get-FileHash $script:CloudImage -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $script:CloudImageSha) {
        throw "Cloud image checksum mismatch.`n  expected $($script:CloudImageSha)`n  got      $got"
    }
    Write-Host '[dirtypipe] checksum OK'
}


function Convert-DirtyPipeImageToVhdx {
    <#
    .SYNOPSIS
    qcow2 -> VHDX. Canonical ships no VHDX for jammy, so conversion is unavoidable.

    .DESCRIPTION
    qemu-img writes a SPARSE file and Hyper-V refuses to attach one ("the system
    cannot find the file specified", unhelpfully). Rewriting the file densely is
    the fix -- learned the hard way in New-AttackerVM.ps1.
    #>
    param([Parameter(Mandatory)][string] $VhdxPath)

    $qemu = (Get-Command qemu-img -ErrorAction SilentlyContinue).Source
    if (-not $qemu) { $qemu = Join-Path $HOME 'scoop\apps\qemu\current\qemu-img.exe' }
    if (-not (Test-Path $qemu)) {
        throw 'Convert-DirtyPipeImageToVhdx: qemu-img not found. Install with: scoop install qemu'
    }

    $sparse = [IO.Path]::ChangeExtension($VhdxPath, '.sparse.vhdx')
    foreach ($p in @($sparse, $VhdxPath)) { if (Test-Path $p) { Remove-Item $p -Force } }

    Write-Host '[dirtypipe] converting cloud image to VHDX (this takes a minute)...'
    & $qemu convert -f qcow2 -O vhdx -o subformat=dynamic $script:CloudImage $sparse
    if ($LASTEXITCODE -ne 0) { throw "qemu-img convert failed ($LASTEXITCODE)" }

    Write-Host '[dirtypipe] rewriting densely (Hyper-V rejects sparse VHDX)'
    fsutil sparse setflag $sparse 0 2>&1 | Out-Null
    Copy-Item $sparse $VhdxPath -Force
    Remove-Item $sparse -Force

    # Cloud images ship a small root; the kernel + Docker + scenario images need room.
    Resize-VHD -Path $VhdxPath -SizeBytes 40GB
    Write-Host "[dirtypipe] VHDX ready: $VhdxPath"
}


function New-DirtyPipeSeedIso {
    <#
    .SYNOPSIS
    Builds the cloud-init NoCloud (CIDATA) seed ISO.

    .DESCRIPTION
    Hyper-V has no cloud-init datasource, so an attached ISO labelled CIDATA is
    the mechanism. Needs oscdimg from the Windows ADK Deployment Tools.

    The two provisioning stages are the EXISTING repo scripts, embedded verbatim
    rather than reimplemented -- they encode the kernel-pinning logic and the
    ABI safety gate, and duplicating that would let the two drift.

    Stage 2 cannot be a plain runcmd: it must execute AFTER the reboot into the
    pinned kernel. It is installed as a systemd oneshot that disables itself.
    #>
    param([Parameter(Mandatory)][string] $IsoPath,
          [Parameter(Mandatory)][string] $PublicKey,
          [Parameter(Mandatory)][string] $NatMac,
          [Parameter(Mandatory)][string] $LabMac)

    # Read from disk, never inlined here. This is a DOUBLE-QUOTED here-string, so
    # PowerShell would interpolate any $(...) or ${...} a shell script contains --
    # an inlined script with $(dpkg-query ...) and || is a parse error, not a
    # runtime surprise. Reading the file and splicing the finished string keeps
    # shell syntax out of PowerShell's parser entirely.
    $stage1  = Get-Content (Join-Path $script:ScenarioDir 'install-old-kernel.sh') -Raw
    $stage1b = Get-Content (Join-Path $script:ScenarioDir 'harden-boot.sh') -Raw
    $stage2  = Get-Content (Join-Path $script:ScenarioDir 'provision.sh') -Raw
    $indent = { param($t) ($t -split "`r?`n" | ForEach-Object { "      $_" }) -join "`n" }

    $userData = @"
#cloud-config
hostname: meta4-dirtypipe
users:
  - name: $($script:GuestUser)
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

  - path: /etc/systemd/system/srb-dirtypipe-stage2.service
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
      ExecStartPost=/bin/sh -c 'systemctl disable srb-dirtypipe-stage2.service; touch /var/lib/srb-dirtypipe-ready'
      StandardOutput=append:/var/log/srb-dirtypipe-stage2.log
      StandardError=append:/var/log/srb-dirtypipe-stage2.log
      [Install]
      WantedBy=multi-user.target

runcmd:
  - [ systemctl, enable, srb-dirtypipe-stage2.service ]
  - [ /bin/bash, /usr/local/sbin/stage1-install-old-kernel.sh ]
  - [ /bin/bash, /usr/local/sbin/stage1b-harden-boot.sh ]

power_state:
  mode: reboot
  message: rebooting into $($script:DirtyPipeVersion)
  timeout: 60
  condition: true
"@

    $metaData = @"
instance-id: meta4-dirtypipe-001
local-hostname: meta4-dirtypipe
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
    # LOWERCASE MACs. netplan/systemd match `macaddress` case-sensitively; an
    # uppercase literal matches nothing, both interfaces stay unconfigured, and
    # the guest boots with no network at all -- which looks identical to "the VM
    # is hung" from the host (heartbeat OK, no ARP, no lease). Cost one build.
    #
    # No set-name: renaming buys nothing here and is another way for the match
    # to fail. Names are irrelevant since nothing addresses them by name.
    $networkConfig = @"
version: 2
ethernets:
  nat:
    match:
      macaddress: "$($NatMac.ToLower())"
    dhcp4: true
    optional: true
  lab:
    match:
      macaddress: "$($LabMac.ToLower())"
    dhcp4: false
    optional: true
    addresses:
      - $($script:GuestCidr)
"@

    $staging = Join-Path $env:TEMP "srb-dirtypipe-cidata"
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging -Force | Out-Null

    # LF endings: cloud-init parses these as YAML and CRLF breaks block scalars.
    # UTF8Encoding($false) — WriteAllText's default in PowerShell 5.1 emits a
    # BOM, which pushes the "#cloud-config" marker off the first bytes. cloud-init
    # then silently treats the payload as unknown and the guest boots unconfigured;
    # the BOM is invisible in every text editor.
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
        throw "New-DirtyPipeSeedIso: user-data must begin with '#cloud-config'; got '$head'"
    }

    $oscdimg = (Get-Command oscdimg.exe -ErrorAction SilentlyContinue).Source
    if (-not $oscdimg) {
        $oscdimg = Get-ChildItem 'C:\Program Files (x86)\Windows Kits' -Recurse -Filter 'oscdimg.exe' `
                     -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $oscdimg) {
        throw 'New-DirtyPipeSeedIso: oscdimg.exe not found. Install the Windows ADK "Deployment Tools" feature.'
    }

    if (Test-Path $IsoPath) { Remove-Item $IsoPath -Force }
    # -j1 keeps Joliet names case-correct; cloud-init looks for lowercase
    # "user-data" and silently ignores the seed if it arrives as "USER-DAT".
    & $oscdimg -j1 -lCIDATA -m -o $staging $IsoPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "oscdimg failed ($LASTEXITCODE)" }
    Write-Host "[dirtypipe] seed ISO: $IsoPath"
}


# Static MACs. Hyper-V only assigns a dynamic MAC at first start, which is after
# the seed ISO has to exist -- and cloud-init matches interfaces by MAC. Fixing
# them here removes the ordering problem and makes rebuilds reproducible.
$script:NatMac = '00:15:5D:40:06:01'
$script:LabMac = '00:15:5D:40:06:02'


function Remove-DirtyPipeVm {
    <#
    .SYNOPSIS
    Tear down any existing VM. MUST run before the VHDX is rewritten.

    .DESCRIPTION
    A running VM holds an exclusive handle on its VHDX, so converting the cloud
    image first fails with "the process cannot access the file ... because it is
    being used by another process". Removing the VM is therefore the first step
    of a rebuild, not part of VM creation.
    #>
    [CmdletBinding()]
    param()

    if (-not (Get-VM -Name $script:DirtyPipeVmName -ErrorAction SilentlyContinue)) { return }
    Write-Host "[dirtypipe] removing existing $($script:DirtyPipeVmName)"
    Stop-VM -Name $script:DirtyPipeVmName -TurnOff -Force -ErrorAction SilentlyContinue
    # Checkpoints keep their own differencing disks open; drop them first or the
    # VHDX stays locked after the VM is gone.
    Get-VMSnapshot -VMName $script:DirtyPipeVmName -ErrorAction SilentlyContinue |
        Remove-VMSnapshot -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Remove-VM -Name $script:DirtyPipeVmName -Force
    Start-Sleep -Seconds 2
}


function New-DirtyPipeVm {
    param([Parameter(Mandatory)][string] $VhdxPath)

    Remove-DirtyPipeVm

    # Gen 2 = UEFI.
    New-VM -Name $script:DirtyPipeVmName -Generation 2 `
           -MemoryStartupBytes (4GB) -VHDPath $VhdxPath -SwitchName $script:BuildSwitch | Out-Null
    Set-VM -Name $script:DirtyPipeVmName -ProcessorCount 2 -AutomaticCheckpointsEnabled $false

    # SECURE BOOT MUST BE OFF, and not as a workaround.
    #
    # Ubuntu's shim revokes superseded signed kernels (SBAT generation numbers,
    # and DBX for the worst cases) precisely to stop an attacker downgrading a
    # patched machine to a vulnerable kernel. 5.13.0-27 is a Jan-2022 kernel
    # that current shim revokes -- which is Secure Boot working exactly as
    # designed. Booting a deliberately vulnerable kernel is this VM's whole
    # purpose, so the two goals are fundamentally incompatible.
    #
    # Confirmed by A/B test: with the MicrosoftUEFICertificateAuthority template
    # the guest never reached the kernel (heartbeat "No Contact", integration
    # services "Lost Communication", VM otherwise "Operating normally" ~6% CPU,
    # cold boot identical). Flipping Secure Boot off and changing nothing else
    # brought heartbeat straight back to OK.
    #
    # Safe here: the VM has no route out after the bake and exists only to host
    # LPE scenario containers.
    Set-VMFirmware -VMName $script:DirtyPipeVmName -EnableSecureBoot Off

    # NIC 1 (created with the VM) = NAT; NIC 2 = the isolated lab segment.
    Get-VMNetworkAdapter -VMName $script:DirtyPipeVmName |
        Set-VMNetworkAdapter -StaticMacAddress ($script:NatMac -replace ':', '')
    Add-VMNetworkAdapter -VMName $script:DirtyPipeVmName -SwitchName $script:LabSwitch `
                         -StaticMacAddress ($script:LabMac -replace ':', '')

    Write-Host "[dirtypipe] created $($script:DirtyPipeVmName): nat=$($script:BuildSwitch) lab=$($script:LabSwitch)"
}


function Invoke-DirtyPipeSsh {
    <#
    .SYNOPSIS
    Run a command in the guest. Never throws; returns exit code + output.

    .DESCRIPTION
    Exists because of a PowerShell 5.1 trap: with $ErrorActionPreference='Stop',
    anything a NATIVE command writes to stderr is wrapped in an ErrorRecord and
    becomes a TERMINATING error. A polling loop that ssh's into a guest which is
    still booting therefore dies on the first "Connection timed out" instead of
    retrying -- which is exactly how the first rebuild failed. Pinning the
    preference to Continue for the duration of the call is the fix.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Command,
          [int] $ConnectTimeout = 5)

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # LogLevel=ERROR: without it ssh prints "Warning: Permanently added ...
        # to the list of known hosts" on first contact, and because stderr is
        # merged into $out that warning becomes the FIRST line of the result --
        # which broke Assert-DirtyPipeAbi's anchored version match even though
        # the guest had booted the right kernel.
        $out = & ssh -i $script:KeyPath -o StrictHostKeyChecking=no `
                     -o UserKnownHostsFile=/dev/null -o BatchMode=yes `
                     -o LogLevel=ERROR -o ConnectTimeout=$ConnectTimeout `
                     "$($script:GuestUser)@$($script:GuestIp)" $Command 2>&1
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output   = (($out | ForEach-Object { "$_" }) -join "`n").Trim()
        }
    } finally {
        $ErrorActionPreference = $prev
    }
}


function Wait-DirtyPipeProvisioned {
    <#
    .SYNOPSIS
    Block until stage 2 has run. A reboot happens mid-flight, so poll the marker
    rather than assuming a single boot.
    #>
    param([int] $TimeoutMinutes = 40)

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    Write-Host "[dirtypipe] waiting for provisioning (up to $TimeoutMinutes min; two boots)..."
    $lastNote = Get-Date
    while ((Get-Date) -lt $deadline) {
        $r = Invoke-DirtyPipeSsh -Command 'test -f /var/lib/srb-dirtypipe-ready && uname -r'
        if ($r.ExitCode -eq 0 -and $r.Output) {
            Write-Host "[dirtypipe] provisioned; running kernel $($r.Output)"
            return $r.Output
        }
        if (((Get-Date) - $lastNote).TotalMinutes -ge 2) {
            $reach = (Invoke-DirtyPipeSsh -Command 'true').ExitCode -eq 0
            Write-Host ("[dirtypipe] still provisioning... ssh={0}" -f $(if ($reach) { 'up, stage2 pending' } else { 'not up yet' }))
            $lastNote = Get-Date
        }
        Start-Sleep -Seconds 20
    }
    throw "Wait-DirtyPipeProvisioned: timed out after $TimeoutMinutes min. Check /var/log/srb-dirtypipe-stage2.log and /var/log/cloud-init-output.log in the guest."
}


function Get-DirtyPipeIpAddress {
    <#
    .SYNOPSIS
    The guest's lab address. Fixed, not discovered.

    .DESCRIPTION
    Discovery via Get-VMNetworkAdapter's IPAddresses depends on the Key-Value
    Pair integration service, whose daemon is absent from stock Ubuntu cloud
    images -- KVP reports "No Contact" and the list is empty, which is exactly
    how the first build of this VM appeared to hang. eth1 is pinned to a known
    address instead, so this needs nothing from the guest.
    #>
    return $script:GuestIp
}


function Assert-DirtyPipeAbi {
    <#
    .SYNOPSIS
    The gate that makes this VM worth building. Wrong ABI => scenarios silently
    stop being exploitable, and verify.sh would "pass" for the wrong reason.
    #>
    param([Parameter(Mandatory)][string] $Running)
    # Unanchored: a stray leading line must not break the match.
    if ($Running -notmatch '5\.13\.0-(\d+)-generic') {
        throw "Assert-DirtyPipeAbi: unexpected kernel '$Running'; wanted $($script:DirtyPipeVersion)"
    }
    $abi = [int]$Matches[1]
    if ($abi -ne $script:DirtyPipeAbi) {
        throw "Assert-DirtyPipeAbi: booted ABI $abi, wanted $($script:DirtyPipeAbi). GRUB pin did not take."
    }
    Write-Host "[dirtypipe] ABI $abi confirmed (< 75 GameOverlay, < 97 nf_tables)"
}


function Install-DirtyPipeLab {
    <#
    .SYNOPSIS
    Full build: verify image -> convert -> seed -> create -> provision -> move
    to the isolated switch -> checkpoint baseline.
    #>
    [CmdletBinding()]
    param()

    # First, before anything touches the VHDX: a running VM holds it open.
    Remove-DirtyPipeVm

    Test-DirtyPipeCloudImage
    $pub  = (Get-Content (New-DirtyPipeSshKey) -Raw).Trim()
    $vhdx = Join-Path $script:VhdRoot "$($script:DirtyPipeVmName).vhdx"
    $iso  = Join-Path $script:VhdRoot "$($script:DirtyPipeVmName)-cidata.iso"

    Convert-DirtyPipeImageToVhdx -VhdxPath $vhdx
    New-DirtyPipeSeedIso -IsoPath $iso -PublicKey $pub `
                      -NatMac $script:NatMac -LabMac $script:LabMac
    New-DirtyPipeVm -VhdxPath $vhdx

    Add-VMDvdDrive -VMName $script:DirtyPipeVmName -Path $iso
    Set-VMFirmware -VMName $script:DirtyPipeVmName `
                   -FirstBootDevice (Get-VMHardDiskDrive -VMName $script:DirtyPipeVmName)

    Start-VM -Name $script:DirtyPipeVmName
    $running = Wait-DirtyPipeProvisioned
    Assert-DirtyPipeAbi -Running $running

    # Seed ISO carries the authorized key; detaching it after the bake keeps the
    # cloud-init datasource from re-running on later boots.
    Get-VMDvdDrive -VMName $script:DirtyPipeVmName | Remove-VMDvdDrive

    # Cut the route out. The scenarios run privileged containers; they have no
    # business reaching the internet once provisioning is done. The lab NIC
    # (fixed address) is untouched, so host-side access is unaffected.
    Write-Host '[dirtypipe] disconnecting the NAT NIC; lab segment only from here'
    Get-VMNetworkAdapter -VMName $script:DirtyPipeVmName |
        Where-Object { $_.MacAddress -eq ($script:NatMac -replace ':', '') } |
        Disconnect-VMNetworkAdapter

    Checkpoint-VM -Name $script:DirtyPipeVmName -SnapshotName 'baseline'
    Write-Host '[dirtypipe] baseline checkpoint taken'
    Write-Host "[dirtypipe] DONE. kernel=$running"
}
