#Requires -RunAsAdministrator
<#
.SYNOPSIS
Builds meta4-kernel: Ubuntu 22.04 on Hyper-V pinned to kernel 5.15.0-25-generic,
with Docker, replacing the Vagrant/VirtualBox definition.

.DESCRIPTION
Deliberately NOT built by AutomatedLab -- its Linux support is materially thinner
than its Windows support, and this VM is a plain Docker host, not a domain. Same
reasoning as meta4/ad-vm/lab/New-AttackerVM.ps1, whose cloud-init/qemu-img
patterns this script reuses.

THE KERNEL IS THE POINT. meta4 scenarios S21 (GameOverlay, CVE-2023-2640/32629)
and S22 (nf_tables UAF, CVE-2024-1086) run as containers INSIDE this VM so they
share its kernel. ABI 25 (5.15.0-25, 22.04 GA, March 2022) predates the
GameOverlay fix (ABI 75) and the nf_tables fix (ABI 97). If the VM boots anything
>= 75 the scenarios silently stop being exploitable and verify.sh "passes" for
the wrong reason -- so provision.sh hard-fails rather than continue.

NETWORK LIFECYCLE, copied from New-AttackerVM: the bake needs the internet (apt,
Docker's repo), but the lab segment SRB-Kernel is Internal with no route out. So
the VM is created on SRB-Build (External), provisioned, and only then moved to
SRB-Kernel. Building directly on the Internal switch makes apt fail in ways
cloud-init reports only in the guest log.

.EXAMPLE
    . .\KernelLab.ps1
    Install-KernelLab
#>

$ErrorActionPreference = 'Stop'

$script:KernelVmName    = 'meta4-kernel'
$script:KernelAbi       = 25
$script:KernelVersion   = "5.15.0-$($script:KernelAbi)-generic"
$script:CloudImage      = 'C:\LabSources\ISOs\jammy-server-cloudimg-amd64.img'
$script:CloudImageSha   = '63dd101826bf6f45c74c4c2e0e0872cfeec4232cb1afcb8aeef8bc16f6c3b1e0'
$script:BuildSwitch     = 'SRB-Build'
$script:LabSwitch       = 'SRB-Kernel'
$script:GuestUser       = 'vagrant'   # kept: run.py's docker-context contract
$script:GuestIp         = '10.20.40.5'
$script:GuestCidr       = '10.20.40.5/24'
$script:GuestGateway    = '10.20.40.1'
$script:SshPort         = 2224        # host-side; 2223 is HS13
$script:KeyPath         = Join-Path $HOME '.ssh\srb_kernel'
$script:VhdRoot         = 'C:\ProgramData\Microsoft\Windows\Virtual Hard Disks'
$script:LabDir          = Split-Path -Parent $PSCommandPath
$script:ScenarioDir     = Split-Path -Parent $script:LabDir


function New-KernelSshKey {
    param([string] $Path = $script:KeyPath)
    if (Test-Path $Path) { Write-Host "[kernel] reusing key $Path"; return "$Path.pub" }
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ssh-keygen -t ed25519 -f $Path -N '""' -C 'srb-kernel' | Out-Null
    if (-not (Test-Path "$Path.pub")) {
        throw 'New-KernelSshKey: ssh-keygen produced no public key. Is the OpenSSH client installed?'
    }
    Write-Host "[kernel] generated $Path"
    return "$Path.pub"
}


function Test-KernelCloudImage {
    <#
    .SYNOPSIS
    Fail loudly if the base image is missing or altered.
    #>
    if (-not (Test-Path $script:CloudImage)) {
        throw @"
Cloud image not found: $($script:CloudImage)
Download it with:
  curl -o "$($script:CloudImage)" https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
"@
    }
    Write-Host '[kernel] verifying image checksum...'
    $got = (Get-FileHash $script:CloudImage -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $script:CloudImageSha) {
        throw "Cloud image checksum mismatch.`n  expected $($script:CloudImageSha)`n  got      $got"
    }
    Write-Host '[kernel] checksum OK'
}


function Convert-KernelImageToVhdx {
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
        throw 'Convert-KernelImageToVhdx: qemu-img not found. Install with: scoop install qemu'
    }

    $sparse = [IO.Path]::ChangeExtension($VhdxPath, '.sparse.vhdx')
    foreach ($p in @($sparse, $VhdxPath)) { if (Test-Path $p) { Remove-Item $p -Force } }

    Write-Host '[kernel] converting cloud image to VHDX (this takes a minute)...'
    & $qemu convert -f qcow2 -O vhdx -o subformat=dynamic $script:CloudImage $sparse
    if ($LASTEXITCODE -ne 0) { throw "qemu-img convert failed ($LASTEXITCODE)" }

    Write-Host '[kernel] rewriting densely (Hyper-V rejects sparse VHDX)'
    fsutil sparse setflag $sparse 0 2>&1 | Out-Null
    Copy-Item $sparse $VhdxPath -Force
    Remove-Item $sparse -Force

    # Cloud images ship a small root; the kernel + Docker + scenario images need room.
    Resize-VHD -Path $VhdxPath -SizeBytes 40GB
    Write-Host "[kernel] VHDX ready: $VhdxPath"
}


function New-KernelSeedIso {
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
          [Parameter(Mandatory)][string] $PublicKey)

    $stage1 = Get-Content (Join-Path $script:ScenarioDir 'install-old-kernel.sh') -Raw
    $stage2 = Get-Content (Join-Path $script:ScenarioDir 'provision.sh') -Raw
    $indent = { param($t) ($t -split "`r?`n" | ForEach-Object { "      $_" }) -join "`n" }

    $userData = @"
#cloud-config
hostname: meta4-kernel
users:
  - name: $($script:GuestUser)
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $PublicKey
ssh_pwauth: false
package_update: true

write_files:
  - path: /usr/local/sbin/stage1-install-old-kernel.sh
    permissions: '0755'
    content: |
$(& $indent $stage1)
  - path: /usr/local/sbin/stage2-provision.sh
    permissions: '0755'
    content: |
$(& $indent $stage2)
  - path: /etc/systemd/system/srb-kernel-stage2.service
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
      ExecStartPost=/bin/sh -c 'systemctl disable srb-kernel-stage2.service; touch /var/lib/srb-kernel-ready'
      StandardOutput=append:/var/log/srb-kernel-stage2.log
      StandardError=append:/var/log/srb-kernel-stage2.log
      [Install]
      WantedBy=multi-user.target

runcmd:
  - [ systemctl, enable, srb-kernel-stage2.service ]
  - [ /bin/bash, /usr/local/sbin/stage1-install-old-kernel.sh ]

power_state:
  mode: reboot
  message: rebooting into $($script:KernelVersion)
  timeout: 60
  condition: true
"@

    $metaData = @"
instance-id: meta4-kernel-001
local-hostname: meta4-kernel
"@

    # BOTH dhcp4 and a static address, deliberately. The bake runs on SRB-Build
    # (External, has DHCP and a route out for apt); the VM then moves to
    # SRB-Kernel (Internal, no DHCP server) where only the static address works.
    # Carrying both means one config survives the move -- DHCP simply stops
    # being answered and the static address remains.
    #
    # This must be network-config, not a netplan file dropped via write_files +
    # `netplan apply` in runcmd: that rewrites config after the interface is
    # already up, and the lab address never comes up
    # (see meta4/ad-vm/lab/New-AttackerVM.ps1:137-145).
    $networkConfig = @"
version: 2
ethernets:
  eth0:
    match:
      name: "e*"
    dhcp4: true
    dhcp4-overrides:
      optional: true
    addresses:
      - $($script:GuestCidr)
"@

    $staging = Join-Path $env:TEMP "srb-kernel-cidata"
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
        throw "New-KernelSeedIso: user-data must begin with '#cloud-config'; got '$head'"
    }

    $oscdimg = (Get-Command oscdimg.exe -ErrorAction SilentlyContinue).Source
    if (-not $oscdimg) {
        $oscdimg = Get-ChildItem 'C:\Program Files (x86)\Windows Kits' -Recurse -Filter 'oscdimg.exe' `
                     -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $oscdimg) {
        throw 'New-KernelSeedIso: oscdimg.exe not found. Install the Windows ADK "Deployment Tools" feature.'
    }

    if (Test-Path $IsoPath) { Remove-Item $IsoPath -Force }
    # -j1 keeps Joliet names case-correct; cloud-init looks for lowercase
    # "user-data" and silently ignores the seed if it arrives as "USER-DAT".
    & $oscdimg -j1 -lCIDATA -m -o $staging $IsoPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "oscdimg failed ($LASTEXITCODE)" }
    Write-Host "[kernel] seed ISO: $IsoPath"
}


function New-KernelVm {
    param([Parameter(Mandatory)][string] $VhdxPath,
          [Parameter(Mandatory)][string] $IsoPath)

    if (Get-VM -Name $script:KernelVmName -ErrorAction SilentlyContinue) {
        Write-Host "[kernel] removing existing $($script:KernelVmName)"
        Stop-VM -Name $script:KernelVmName -TurnOff -Force -ErrorAction SilentlyContinue
        Remove-VM -Name $script:KernelVmName -Force
    }

    # Gen 2 = UEFI. Ubuntu cloud images boot it, but Hyper-V's default secure
    # boot template is the Microsoft one and rejects shim -- use the UEFI CA.
    $vm = New-VM -Name $script:KernelVmName -Generation 2 `
                 -MemoryStartupBytes (4GB) -VHDPath $VhdxPath -SwitchName $script:BuildSwitch
    Set-VM -Name $script:KernelVmName -ProcessorCount 2 -AutomaticCheckpointsEnabled $false
    Set-VMFirmware -VMName $script:KernelVmName -SecureBootTemplate 'MicrosoftUEFICertificateAuthority'
    Add-VMDvdDrive -VMName $script:KernelVmName -Path $IsoPath
    Set-VMFirmware -VMName $script:KernelVmName -FirstBootDevice (Get-VMHardDiskDrive -VMName $script:KernelVmName)
    Write-Host "[kernel] created $($script:KernelVmName) on $($script:BuildSwitch)"
    return $vm
}


function Wait-KernelProvisioned {
    <#
    .SYNOPSIS
    Block until stage 2 has run. Reboot happens mid-flight, so poll the marker.
    #>
    param([int] $TimeoutMinutes = 40)

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    Write-Host "[kernel] waiting for provisioning (up to $TimeoutMinutes min; two boots)..."
    while ((Get-Date) -lt $deadline) {
        $ip = Get-KernelIpAddress
        if ($ip) {
            $probe = ssh -i $script:KeyPath -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null `
                         -o ConnectTimeout=5 -o BatchMode=yes "$($script:GuestUser)@$ip" `
                         'test -f /var/lib/srb-kernel-ready && uname -r' 2>$null
            if ($LASTEXITCODE -eq 0 -and $probe) {
                Write-Host "[kernel] provisioned; running kernel $probe"
                return $probe.Trim()
            }
        }
        Start-Sleep -Seconds 20
    }
    throw "Wait-KernelProvisioned: timed out after $TimeoutMinutes min. Check /var/log/srb-kernel-stage2.log in the guest."
}


function Get-KernelIpAddress {
    (Get-VMNetworkAdapter -VMName $script:KernelVmName -ErrorAction SilentlyContinue).IPAddresses |
        Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -ne '127.0.0.1' } |
        Select-Object -First 1
}


function Assert-KernelAbi {
    <#
    .SYNOPSIS
    The gate that makes this VM worth building. Wrong ABI => scenarios silently
    stop being exploitable, and verify.sh would "pass" for the wrong reason.
    #>
    param([Parameter(Mandatory)][string] $Running)
    if ($Running -notmatch '^5\.15\.0-(\d+)-generic') {
        throw "Assert-KernelAbi: unexpected kernel '$Running'; wanted $($script:KernelVersion)"
    }
    $abi = [int]$Matches[1]
    if ($abi -ne $script:KernelAbi) {
        throw "Assert-KernelAbi: booted ABI $abi, wanted $($script:KernelAbi). GRUB pin did not take."
    }
    Write-Host "[kernel] ABI $abi confirmed (< 75 GameOverlay, < 97 nf_tables)"
}


function Install-KernelLab {
    <#
    .SYNOPSIS
    Full build: verify image -> convert -> seed -> create -> provision -> move
    to the isolated switch -> checkpoint baseline.
    #>
    [CmdletBinding()]
    param()

    Test-KernelCloudImage
    $pub  = (Get-Content (New-KernelSshKey) -Raw).Trim()
    $vhdx = Join-Path $script:VhdRoot "$($script:KernelVmName).vhdx"
    $iso  = Join-Path $script:VhdRoot "$($script:KernelVmName)-cidata.iso"

    Convert-KernelImageToVhdx -VhdxPath $vhdx
    New-KernelSeedIso -IsoPath $iso -PublicKey $pub
    New-KernelVm -VhdxPath $vhdx -IsoPath $iso | Out-Null

    Start-VM -Name $script:KernelVmName
    $running = Wait-KernelProvisioned
    Assert-KernelAbi -Running $running

    # Seed ISO carries the authorized key; detaching it after the bake keeps the
    # cloud-init datasource from re-running on later boots.
    Get-VMDvdDrive -VMName $script:KernelVmName | Remove-VMDvdDrive

    Write-Host "[kernel] moving NIC to $($script:LabSwitch)"
    Connect-VMNetworkAdapter -VMName $script:KernelVmName -SwitchName $script:LabSwitch

    Checkpoint-VM -Name $script:KernelVmName -SnapshotName 'baseline'
    Write-Host '[kernel] baseline checkpoint taken'
    Write-Host "[kernel] DONE. kernel=$running"
}
