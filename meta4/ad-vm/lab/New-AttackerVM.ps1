#Requires -RunAsAdministrator
<#
.SYNOPSIS
Builds attacker01: Ubuntu Server on Hyper-V with the pinned Kali tooling
container loaded.

.DESCRIPTION
Deliberately NOT built by AutomatedLab: its Linux support is materially thinner
than its Windows support, and keeping this VM independent makes it the easiest
machine for a reviewer to substitute.

NETWORK LIFECYCLE. attacker01 needs the internet during the bake -- cloud-init
installs docker.io and the tooling image has to be loaded -- but the AD segment
has no route out by design. So the VM is created on SRB-Build (External),
provisioned, and only then moved to SRB-Lab. Creating it directly on SRB-Lab,
as the first draft did, makes `packages: [docker.io]` silently fail.
#>

function New-AttackerSshKey {
    <#
    .SYNOPSIS
    Generates the keypair the host-side probes authenticate with.
    #>
    [CmdletBinding()]
    param([string] $KeyPath = (Join-Path $HOME '.ssh\srb_attacker'))

    if (Test-Path $KeyPath) {
        Write-Host "[attacker] reusing existing key $KeyPath"
        return "$KeyPath.pub"
    }

    $dir = Split-Path $KeyPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    ssh-keygen -t ed25519 -f $KeyPath -N '""' -C 'srb-attacker' | Out-Null
    if (-not (Test-Path "$KeyPath.pub")) {
        throw 'New-AttackerSshKey: ssh-keygen did not produce a public key. Is OpenSSH Client installed?'
    }

    Write-Host "[attacker] generated $KeyPath"
    return "$KeyPath.pub"
}

function New-CloudInitSeedIso {
    <#
    .SYNOPSIS
    Renders user-data from its template and packs a NoCloud seed ISO.
    .DESCRIPTION
    Hyper-V has no cloud-init datasource of its own, so NoCloud via an attached
    ISO labelled CIDATA is the mechanism. Requires oscdimg from the Windows ADK
    Deployment Tools.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $CloudInitDir,
        [Parameter(Mandatory)] [string] $OutputIsoPath,
        [string] $PublicKeyPath = (Join-Path $HOME '.ssh\srb_attacker.pub')
    )

    # The ADK does not add oscdimg to PATH, so Get-Command alone finds it only
    # if the operator added it by hand. Fall back to the standard ADK layout.
    $oscdimgPath = (Get-Command oscdimg.exe -ErrorAction SilentlyContinue).Source
    if (-not $oscdimgPath) {
        $oscdimgPath = Get-ChildItem 'C:\Program Files (x86)\Windows Kits' -Recurse -Filter 'oscdimg.exe' -ErrorAction SilentlyContinue |
            Where-Object FullName -like '*amd64*' |
            Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $oscdimgPath) {
        throw 'New-CloudInitSeedIso: oscdimg.exe not found on PATH or under the Windows Kits directory. Install the Windows ADK "Deployment Tools" feature.'
    }
    Write-Verbose "[attacker] using oscdimg at $oscdimgPath"
    if (-not (Test-Path $PublicKeyPath)) {
        throw "New-CloudInitSeedIso: $PublicKeyPath not found. Run New-AttackerSshKey first."
    }

    $template = Join-Path $CloudInitDir 'user-data.template'
    if (-not (Test-Path $template)) { throw "New-CloudInitSeedIso: $template not found" }

    $pubkey = (Get-Content -LiteralPath $PublicKeyPath -Raw).Trim()
    $rendered = (Get-Content -LiteralPath $template -Raw) -replace '__SSH_PUBKEY__', $pubkey

    # user-data must sit beside meta-data in the ISO root, with no extension.
    $staging = Join-Path ([IO.Path]::GetTempPath()) "srb-cidata-$PID"
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        Set-Content -LiteralPath (Join-Path $staging 'user-data') -Value $rendered -Encoding utf8 -NoNewline
        Copy-Item -LiteralPath (Join-Path $CloudInitDir 'meta-data') -Destination $staging

        # -j1 adds a Joliet tree alongside ISO9660. Without it oscdimg writes
        # plain ISO9660, which does not preserve case, so the files land as
        # USER-DATA / META-DATA. cloud-init's NoCloud datasource looks for
        # lowercase user-data / meta-data and would silently find neither --
        # leaving the guest with no SSH key and no static address, which then
        # presents as every host-side probe timing out for no obvious reason.
        # Linux prefers the Joliet tree on mount, so names keep their case.
        #
        # -n is deliberately NOT passed: oscdimg rejects it alongside -j1
        # ("With -j1 and -j2, cannot use -n, -nt, or -d"). Joliet already
        # allows the long names -n would have provided.
        & $oscdimgPath -lCIDATA -j1 $staging $OutputIsoPath
        if ($LASTEXITCODE -ne 0) {
            throw "New-CloudInitSeedIso: oscdimg failed with exit code $LASTEXITCODE"
        }
        Write-Host "[attacker] seed ISO written to $OutputIsoPath"
    }
    finally {
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Convert-CloudImageToVhdx {
    <#
    .SYNOPSIS
    Converts an Ubuntu cloud image (.img, qcow2) to a dynamic VHDX.

    .DESCRIPTION
    Canonical publishes noble as qcow2 only -- no .vhd under
    cloud-images.ubuntu.com/releases/noble/release/ -- so a conversion step is
    unavoidable on Hyper-V. qemu-img comes from `scoop install qemu`.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ImagePath,
        [Parameter(Mandatory)] [string] $VhdxPath,
        [uint64] $ResizeToBytes = 40GB
    )

    $qemu = (Get-Command qemu-img -ErrorAction SilentlyContinue).Source
    if (-not $qemu) {
        $qemu = Join-Path $HOME 'scoop\apps\qemu\current\qemu-img.exe'
    }
    if (-not (Test-Path $qemu)) {
        throw 'Convert-CloudImageToVhdx: qemu-img not found. Install it with: scoop install qemu'
    }

    if (Test-Path -LiteralPath $VhdxPath) {
        Remove-Item -LiteralPath $VhdxPath -Force
    }

    Write-Host "[attacker] converting cloud image -> VHDX (this takes a minute)"
    & $qemu convert -f qcow2 -O vhdx -o subformat=dynamic $ImagePath $VhdxPath
    if ($LASTEXITCODE -ne 0) { throw "Convert-CloudImageToVhdx: qemu-img convert failed ($LASTEXITCODE)" }

    # Cloud images ship ~3.5 GB; grow so there is room for the tooling image.
    Resize-VHD -Path $VhdxPath -SizeBytes $ResizeToBytes -ErrorAction SilentlyContinue
    Write-Host "[attacker] VHDX ready: $([math]::Round((Get-Item $VhdxPath).Length/1GB,2)) GB on disk"
}

function New-AttackerVMFromCloudImage {
    <#
    .SYNOPSIS
    Builds attacker01 from a converted Ubuntu cloud image. No installer.

    .DESCRIPTION
    Preferred over the live-server ISO route. A cloud image is already
    installed and boots straight into cloud-init, which consumes the NoCloud
    seed with no prompts.

    The ISO route cannot be made unattended without remastering: subiquity
    requires `autoinstall` on the KERNEL COMMAND LINE, and per Canonical's
    quickstart the only ways to supply it are interrupting boot to edit GRUB or
    rebuilding the ISO. A NoCloud seed alone always leaves the installer
    waiting at its confirmation prompt -- which from the host looks exactly
    like a hung VM: Running, 0% CPU, heartbeat OK, zero bytes written.

    Created on SRB-Build because cloud-init installs docker.io and needs
    internet; Move-AttackerToLabNetwork puts it on the isolated segment after.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $VhdxPath,
        [Parameter(Mandatory)] [string] $SeedIsoPath,
        [string] $VMName = 'attacker01'
    )

    if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
        throw "New-AttackerVMFromCloudImage: $VMName already exists. Remove it first."
    }

    New-VM -Name $VMName -Generation 2 -MemoryStartupBytes 3GB `
        -VHDPath $VhdxPath -SwitchName 'SRB-Build' | Out-Null

    Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false -StartupBytes 3GB
    Set-VMProcessor -VMName $VMName -Count 2

    # Ubuntu is signed under the Microsoft UEFI CA, not the Windows template
    # Hyper-V defaults Gen2 VMs to.
    Set-VMFirmware -VMName $VMName -SecureBootTemplate 'MicrosoftUEFICertificateAuthority'

    # NoCloud seed as a DVD; cloud-init finds it by the CIDATA volume label.
    Add-VMDvdDrive -VMName $VMName -Path $SeedIsoPath

    # Boot from the VHDX, not the seed.
    $osDisk = Get-VMHardDiskDrive -VMName $VMName | Select-Object -First 1
    Set-VMFirmware -VMName $VMName -FirstBootDevice $osDisk

    Set-VM -Name $VMName -AutomaticCheckpointsEnabled $false `
        -CheckpointType Standard `
        -AutomaticStartAction Nothing -AutomaticStopAction ShutDown

    Write-Host "[attacker] $VMName created from cloud image on SRB-Build"
}

function New-AttackerVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $UbuntuIsoPath,
        [Parameter(Mandatory)] [string] $VhdxPath,
        [Parameter(Mandatory)] [string] $SeedIsoPath,
        [string] $VMName = 'attacker01'
    )

    if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
        Write-Host "[attacker] $VMName already exists"
        return
    }

    New-VHD -Path $VhdxPath -SizeBytes 40GB -Dynamic | Out-Null

    # Created on SRB-Build so cloud-init can reach the internet. Moved to
    # SRB-Lab by Move-AttackerToLabNetwork once provisioning is done.
    New-VM -Name $VMName -Generation 2 -MemoryStartupBytes 3GB `
        -VHDPath $VhdxPath -SwitchName 'SRB-Build' | Out-Null

    # Fixed memory: this guest runs a Docker runtime, and an OOM-killed tooling
    # container mid-PoC produces nondeterministic false passes.
    Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false -StartupBytes 3GB
    Set-VMProcessor -VMName $VMName -Count 2

    # Gen2 defaults to the Windows Secure Boot template, which will refuse to
    # boot Ubuntu. Ubuntu is signed under the Microsoft UEFI CA.
    Set-VMFirmware -VMName $VMName -SecureBootTemplate 'MicrosoftUEFICertificateAuthority'

    Add-VMDvdDrive -VMName $VMName -Path $UbuntuIsoPath
    Add-VMDvdDrive -VMName $VMName -Path $SeedIsoPath

    $dvd = Get-VMDvdDrive -VMName $VMName | Select-Object -First 1
    Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd

    Set-VM -Name $VMName -AutomaticCheckpointsEnabled $false `
        -CheckpointType Standard `
        -AutomaticStartAction Nothing -AutomaticStopAction ShutDown

    Write-Host "[attacker] $VMName created on SRB-Build (build network)"
    Write-Host "[attacker] start it, complete the Ubuntu install, then run:"
    Write-Host "[attacker]   Install-AttackerTooling; Move-AttackerToLabNetwork"
}

function Install-AttackerTooling {
    <#
    .SYNOPSIS
    Loads the pinned srb-attacker image into the VM while it still has internet.
    #>
    [CmdletBinding()]
    param(
        [string] $BuildHost = '',
        [string] $KeyPath   = (Join-Path $HOME '.ssh\srb_attacker'),
        [string] $ImageTag  = 'srb-attacker:1'
    )

    if (-not $BuildHost) {
        throw 'Install-AttackerTooling: pass -BuildHost with the DHCP address the VM got on SRB-Build (check the Hyper-V console).'
    }

    $tar = Join-Path ([IO.Path]::GetTempPath()) 'srb-attacker.tar'
    Write-Host "[attacker] exporting $ImageTag"
    docker save $ImageTag -o $tar
    if ($LASTEXITCODE -ne 0) { throw "Install-AttackerTooling: docker save failed. Build it first: docker build -t $ImageTag lab/attacker" }

    Write-Host "[attacker] copying image to $BuildHost"
    scp -o StrictHostKeyChecking=no -i $KeyPath $tar "vagrant@${BuildHost}:/tmp/srb-attacker.tar"
    if ($LASTEXITCODE -ne 0) { throw 'Install-AttackerTooling: scp failed' }

    ssh -o StrictHostKeyChecking=no -o BatchMode=yes -i $KeyPath "vagrant@$BuildHost" `
        'sudo docker load -i /tmp/srb-attacker.tar && rm -f /tmp/srb-attacker.tar && sudo docker images'
    if ($LASTEXITCODE -ne 0) { throw 'Install-AttackerTooling: docker load failed' }

    Remove-Item $tar -Force -ErrorAction SilentlyContinue
    Write-Host '[attacker] tooling image loaded'
}

function Move-AttackerToLabNetwork {
    <#
    .SYNOPSIS
    Detaches the build network and puts attacker01 on the isolated AD segment.
    #>
    [CmdletBinding()]
    param([string] $VMName = 'attacker01')

    Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue
    while ((Get-VM -Name $VMName).State -ne 'Off') { Start-Sleep -Seconds 2 }

    Get-VMNetworkAdapter -VMName $VMName | Connect-VMNetworkAdapter -SwitchName 'SRB-Lab'

    # The install media is no longer needed and an attached DVD is one more way
    # for a scenario to reach something it should not.
    Get-VMDvdDrive -VMName $VMName | Remove-VMDvdDrive

    Write-Host "[attacker] $VMName moved to SRB-Lab; DVD drives removed"
    Write-Host '[attacker] start it and confirm with: Test-LabEgress'
}
